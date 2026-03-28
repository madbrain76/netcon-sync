"""
Unit tests for trust.py error formatting helpers.
"""

import sys
from pathlib import Path

import nss.error

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from trust import format_nss_error


def test_format_nss_error_uses_actual_connection_reset_code():
    error = nss.error.NSPRError("connect failed", nss.error.PR_CONNECT_RESET_ERROR)

    message = format_nss_error("UniFi Controller", "https://controller.example", error, "./unifi_climgr.py")

    assert "PR_CONNECT_RESET_ERROR" in message
    assert "TCP connection reset by peer." in message
    assert "transport-level connection failure" in message
    assert "CERTIFICATE NOT TRUSTED" not in message
    assert "trust --server" not in message


def test_format_nss_error_keeps_trust_guidance_for_untrusted_issuer():
    error = nss.error.NSPRError("connect failed", nss.error.SEC_ERROR_UNTRUSTED_ISSUER)

    message = format_nss_error("UniFi Controller", "https://controller.example", error, "./unifi_climgr.py")

    assert "SEC_ERROR_UNTRUSTED_ISSUER" in message
    assert "issuer has been marked as not trusted" in message
    assert "./unifi_climgr.py trust --server https://controller.example" in message
