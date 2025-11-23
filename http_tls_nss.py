# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
HTTP/HTTPS client using NSS/NSPR for TLS.

Transparently replaces the socket layer with NSS while keeping
all HTTP processing (headers, redirects, etc.) unchanged.

Provides:
- NSPRNSSURLOpener: Standard urllib opener with NSS sockets underneath
- get_server_certificate(): Extract server certificate for verification/import
"""

import http.client
import http.cookiejar
import urllib.request
import urllib.error
import socket
import hashlib
import nss.io
import nss.ssl


class _ReadWrapper:
    """Wraps file objects to handle partial reads from NSS and preserve socket for keep-alive."""
    
    def __init__(self, fileobj):
        self._fileobj = fileobj
    
    def read(self, amt=-1):
        """Read exactly amt bytes (or all remaining if amt < 0)."""
        if amt is None or amt < 0:
            return self._fileobj.read(amt)
        
        result = b''
        while len(result) < amt:
            chunk = self._fileobj.read(amt - len(result))
            if not chunk:
                break
            result += chunk
        
        return result
    
    def close(self):
        """Called when response is complete. Keep socket open for keep-alive."""
        pass
    
    def flush(self):
        """Called during cleanup. No-op for keep-alive."""
        pass
    
    def __getattr__(self, name):
        return getattr(self._fileobj, name)


class SocketWrapper:
    """Wraps NSS socket to look like a standard socket for http.client."""
    
    def __init__(self, sock):
        self._sock = sock
        self._fileobj = None
    
    def makefile(self, mode='rb', buffering=-1):
        """Create file object from socket once and cache it."""
        if self._fileobj is None:
            raw_fileobj = self._sock.makefile(mode, buffering)
            self._fileobj = _ReadWrapper(raw_fileobj)
        return self._fileobj
    
    def send(self, data):
        return self._sock.send(data)
    
    def sendall(self, data):
        if hasattr(self._sock, 'sendall') and type(self._sock).__name__ != 'SSLSocket':
            return self._sock.sendall(data)
        else:
            total = 0
            while total < len(data):
                sent = self._sock.send(data[total:])
                if sent == 0:
                    raise RuntimeError("send() returned 0")
                total += sent
            return total
    
    def recv(self, bufsize, flags=0):
        return self._sock.recv(bufsize)
    
    def recv_into(self, buffer, nbytes=None, flags=0):
        if nbytes is None:
            nbytes = len(buffer)
        data = self._sock.recv(nbytes)
        n = len(data)
        buffer[:n] = data
        return n
    
    def close(self):
        """Close the underlying socket."""
        if hasattr(self._sock, 'close'):
            try:
                self._sock.close()
            except Exception:
                pass
    
    def __getattr__(self, name):
        return getattr(self._sock, name)


def _create_nss_socket(hostname, port, use_tls):
    """Create an NSS/NSPR socket."""
    # Resolve hostname
    addr_info = nss.io.AddrInfo(hostname)
    net_addrs = list(addr_info)
    
    net_addr = None
    for addr in net_addrs:
        if addr.family == nss.io.PR_AF_INET:
            net_addr = addr
            break
    if net_addr is None and net_addrs:
        net_addr = net_addrs[0]
    
    if net_addr is None:
        raise RuntimeError(f"Could not resolve {hostname}")
    
    net_addr.port = port
    
    if use_tls:
        # Create and configure NSS socket first, then connect
        nss_socket = nss.ssl.SSLSocket(net_addr.family)
        nss_socket.set_hostname(hostname)
        nss_socket.set_ssl_option(nss.ssl.SSL_SECURITY, True)
        nss_socket.set_ssl_option(nss.ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        
        # TLS handshake happens during connect
        # NSS automatically validates certificates against trusted CAs in the database
        nss_socket.connect(net_addr)
        return nss_socket
    else:
        # Create plain NSPR socket for HTTP
        nspr_socket = nss.io.Socket(net_addr.family)
        nspr_socket.connect(net_addr)
        return nspr_socket


class _NSHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that uses NSS/NSPR for TLS instead of stdlib SSL."""
    
    def __init__(self, host, port=None, **kwargs):
        # urllib may pass "host:port" as a single string
        if port is None and ':' in host:
            host, port_str = host.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                pass  # Keep as-is if not a valid port
        
        # Remove SSL kwargs and call parent without them
        kwargs.pop('context', None)
        kwargs.pop('check_hostname', None)
        # Call HTTPConnection init, skip HTTPSConnection's SSL setup
        http.client.HTTPConnection.__init__(self, host, port, **kwargs)
        if self.port is None:
            self.port = 443
    
    def connect(self):
        """Connect using NSS socket instead of stdlib SSL."""
        nss_socket = _create_nss_socket(self.host, self.port, use_tls=True)
        self.sock = SocketWrapper(nss_socket)


class _NSHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that uses NSPR for connections."""
    
    def __init__(self, host, port=None, **kwargs):
        # urllib may pass "host:port" as a single string
        if port is None and ':' in host:
            host, port_str = host.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                pass  # Keep as-is if not a valid port
        
        # Call parent init
        http.client.HTTPConnection.__init__(self, host, port, **kwargs)
        if self.port is None:
            self.port = 80
    
    def connect(self):
        """Connect using NSPR socket."""
        nss_socket = _create_nss_socket(self.host, self.port, use_tls=False)
        self.sock = SocketWrapper(nss_socket)


class _CustomHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler using NSS connection class."""
    
    def https_open(self, req):
        return self.do_open(_NSHTTPSConnection, req)


class _CustomHTTPHandler(urllib.request.HTTPHandler):
    """HTTP handler using NSPR connection class."""
    
    def http_open(self, req):
        return self.do_open(_NSHTTPConnection, req)


class NSPRNSSURLOpener:
    """
    Standard urllib opener with NSS/NSPR sockets and cookie handling.
    
    Replaces socket layer with NSS/NSPR while keeping all urllib machinery.
    Automatically preserves session state via HTTP cookies.
    All HTTP protocol handling (headers, redirects, etc.) is unchanged.
    """
    
    def __init__(self):
        """Initialize opener with NSS connection classes and cookie jar."""
        # Create a cookie jar to preserve session state
        self.cookie_jar = http.cookiejar.CookieJar()
        
        # Create handlers that use our NSS connection classes
        https_handler = _CustomHTTPSHandler()
        http_handler = _CustomHTTPHandler()
        cookie_handler = urllib.request.HTTPCookieProcessor(self.cookie_jar)
        
        # build_opener() includes all default processors plus our custom ones
        self.opener = urllib.request.build_opener(
            https_handler,
            http_handler,
            cookie_handler
        )
    
    def request(self, method, url, data=None, headers=None):
        """
        Make an HTTP request (matching requests.Session.request signature).
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Full URL
            data: Request body (bytes or None)
            headers: Dict of headers (or None)
        
        Returns:
            urllib.response response object
        """
        if headers is None:
            headers = {}
        
        req = urllib.request.Request(url, data=data, headers=headers)
        req.get_method = lambda: method
        
        try:
            response = self.opener.open(req)
            return response
        except urllib.error.HTTPError:
            raise


def get_server_certificate(hostname, port=443):
    """
    Extract server certificate via NSS/NSPR socket.
    
    Connects to server, performs TLS handshake,
    and extracts the certificate via auth_certificate_callback.
    
    Assumes NSS database is already initialized (done at application startup).
    Uses the NSS database at ~/.netcon-sync for certificate validation.
    
    Returns certificate details including raw DER data for import into NSS database.
    
    Args:
        hostname (str): Server hostname
        port (int): Server port (default: 443)
    
    Returns:
        dict: Contains:
            - 'der': Raw DER certificate data (bytes)
            - 'sha1': SHA-1 fingerprint (hex string)
            - 'sha256': SHA-256 fingerprint (hex string)
    
    Raises:
        Exception: If connection or certificate extraction fails
    """
    extracted_cert = {}
    
    def auth_cert_callback(sock, check_sig, is_server):
        """Certificate authentication callback - called during TLS handshake."""
        try:
            peer_cert = sock.get_peer_certificate()
            if peer_cert is not None:
                extracted_cert['der'] = peer_cert.der_data
            return True
        except Exception:
            return True
    
    try:
        # Resolve hostname
        addr_info = nss.io.AddrInfo(hostname)
        net_addrs = list(addr_info)
        
        net_addr = None
        for addr in net_addrs:
            if addr.family == nss.io.PR_AF_INET:
                net_addr = addr
                break
        if net_addr is None and net_addrs:
            net_addr = net_addrs[0]
        
        if net_addr is None:
            raise RuntimeError(f"Could not resolve {hostname}")
        
        net_addr.port = port
        
        # Create and configure NSS socket
        nss_socket = nss.ssl.SSLSocket(net_addr.family)
        nss_socket.set_hostname(hostname)
        nss_socket.set_ssl_option(nss.ssl.SSL_SECURITY, True)
        nss_socket.set_ssl_option(nss.ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        
        # Set auth certificate callback to extract cert during handshake
        nss_socket.set_auth_certificate_callback(auth_cert_callback)
        
        # Connect (socket connection established)
        nss_socket.connect(net_addr)
        
        # Trigger TLS handshake by sending data
        try:
            nss_socket.send(b"")
        except Exception:
            pass  # Send may fail, but handshake is triggered
        
        # Get the extracted certificate
        if not extracted_cert.get('der'):
            raise RuntimeError("Failed to extract server certificate")
        
        der_data = extracted_cert['der']
        
        # Calculate fingerprints
        sha1 = hashlib.sha1(der_data).hexdigest().upper()
        sha256 = hashlib.sha256(der_data).hexdigest().upper()
        
        # Close socket
        nss_socket.close()
        
        return {
            "der": der_data,
            "sha1": sha1,
            "sha256": sha256
        }
        
    except Exception as e:
        raise Exception(f"Failed to retrieve certificate from {hostname}:{port}: {e}")
