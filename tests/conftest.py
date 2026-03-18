"""
Shared fixtures and utilities for netcon-sync tests.
"""

import os
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test configuration
TEST_CONFIG = {
    "UNIFI_NETWORK_URL": os.getenv("UNIFI_NETWORK_URL", "https://unifi.local"),
    "UNIFI_USERNAME": os.getenv("UNIFI_USERNAME", "admin"),
    "UNIFI_PASSWORD": os.getenv("UNIFI_PASSWORD", "password"),
    "UNIFI_SITE_ID": os.getenv("UNIFI_SITE_ID", "default"),
    "DEFAULT_DOMAIN": os.getenv("DEFAULT_DOMAIN", "local"),
}


# Fixtures for test data
@pytest.fixture
def sample_client():
    """Sample UniFi client data."""
    return {
        "_id": "client-123",
        "mac": "aa:bb:cc:dd:ee:ff",
        "hostname": "test-device",
        "name": "Test Device",
        "note": "Test note",
        "is_guest": False,
        "is_wired": True,
        "is_11ax": False,
        "ok_to_leave": True,
        "usergroup_id": "",
        "vlan": "",
        "fixed_ip": "192.168.1.100",
        "use_fixedip": True,
        "local_dns_record_enabled": True,
        "local_dns_record": "test.local",
        "fixed_ap_enabled": True,
        "fixed_ap_mac": "11:22:33:44:55:66",
        "site_id": "default",
        "first_seen": int(datetime.now().timestamp() * 1000),
        "last_seen": int(datetime.now().timestamp() * 1000),
        "is_connected_live": True,
        "is_ap_locked": False,
    }


@pytest.fixture
def sample_ap():
    """Sample UniFi AP data."""
    return {
        "_id": "ap-123",
        "mac": "11:22:33:44:55:66",
        "name": "Living Room AP",
        "type": "uap",
        "type_string": "UAP",
        "model": "U7-Pro",
        "adopted": True,
        "adopt_status": 1,
        "up": True,
        "connect_ip": "192.168.1.10",
        "state": 0,
        "site_id": "default",
        "firmware_version": "6.2.28",
        "uplink": {"type": "wire", "up": True},
    }


@pytest.fixture
def sample_ssid():
    """Sample UniFi SSID data."""
    return {
        "_id": "ssid-123",
        "name": "Guest WiFi",
        "enabled": True,
        "site_id": "default",
        "bssid": "11:22:33:44:55:66",
        "wlangroup_id": "default",
        "xhide": False,
        "is_guest": True,
        "wips_mode": "none",
        "wips_ap_ids": [],
    }


@pytest.fixture
def sample_ssids():
    """Sample UniFi SSIDs."""
    return [
        {
            "_id": "ssid-1",
            "name": "Main WiFi",
            "enabled": True,
            "site_id": "default",
        },
        {
            "_id": "ssid-2",
            "name": "Guest WiFi",
            "enabled": False,
            "site_id": "default",
        },
        {
            "_id": "ssid-3",
            "name": "IOT WiFi",
            "enabled": True,
            "site_id": "default",
        },
    ]


@pytest.fixture
def sample_clients():
    """Sample UniFi clients."""
    return [
        {
            "_id": "client-1",
            "mac": "aa:bb:cc:dd:ee:01",
            "hostname": "phone-1",
            "name": "John's Phone",
            "is_connected_live": True,
            "is_guest": False,
            "is_wired": False,
        },
        {
            "_id": "client-2",
            "mac": "aa:bb:cc:dd:ee:02",
            "hostname": "laptop-1",
            "name": "Work Laptop",
            "is_connected_live": True,
            "is_guest": False,
            "is_wired": True,
        },
        {
            "_id": "client-3",
            "mac": "aa:bb:cc:dd:ee:03",
            "hostname": "iot-device",
            "name": "",
            "is_connected_live": False,
            "is_guest": False,
            "is_wired": True,
        },
    ]


@pytest.fixture
def sample_devices():
    """Sample UniFi devices (APs, gateways, etc.)."""
    return [
        {
            "_id": "ap-1",
            "mac": "11:22:33:44:55:66",
            "name": "Living Room AP",
            "type": "uap",
            "type_string": "UAP",
            "model": "U7-Pro",
            "adopted": True,
            "adopt_status": 1,
            "up": True,
            "connect_ip": "192.168.1.10",
            "site_id": "default",
        },
        {
            "_id": "ap-2",
            "mac": "11:22:33:44:55:77",
            "name": "Office AP",
            "type": "uap",
            "type_string": "UAP",
            "model": "U6-LR",
            "adopted": True,
            "adopt_status": 1,
            "up": True,
            "connect_ip": "192.168.1.11",
            "site_id": "default",
        },
        {
            "_id": "gateway-1",
            "mac": "11:22:33:44:55:88",
            "name": "UniFi Gateway",
            "type": "usg",
            "type_string": "USG",
            "model": "USG-Pro-XG",
            "adopted": True,
            "adopt_status": 1,
            "up": True,
            "connect_ip": "192.168.1.1",
            "site_id": "default",
        },
    ]


@pytest.fixture
def mock_unifi_response():
    """Create a mock HTTP response object."""
    response = Mock()
    response.getcode = Mock(return_value=200)
    response.info = Mock(return_value={})
    response.read = Mock(return_value=b'{"meta": {"rc": "ok"}}')
    response.close = Mock()
    return response


@pytest.fixture
def mock_api_call_success():
    """Mock that simulates successful API calls."""
    def mock_call(method, endpoint, **kwargs):
        return {"meta": {"rc": "ok"}}
    return mock_call


@pytest.fixture
def mock_api_call_failure():
    """Mock that simulates failed API calls."""
    def mock_call(method, endpoint, **kwargs):
        raise Exception("API call failed")
    return mock_call


@pytest.fixture
def mock_get_all_unifi_clients():
    """Mock for get_all_unifi_clients."""
    def mock_call():
        return [
            {
                "mac": "aa:bb:cc:dd:ee:01",
                "hostname": "test-device-1",
                "name": "Test Device 1",
                "note": "Test note 1",
                "is_connected_live": True,
                "fixed_ap_enabled": False,
                "use_fixedip": False,
                "local_dns_record_enabled": False,
            },
        ]
    return mock_call


# Context manager for temporarily setting environment variables
class TempEnv:
    """Context manager for temporarily setting environment variables."""

    def __init__(self, **kwargs):
        self.new_env = kwargs

    def __enter__(self):
        self.old_env = {}
        for key, value in self.new_env.items():
            self.old_env[key] = os.environ.get(key)
            os.environ[key] = value

    def __exit__(self, *args):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture
def temp_env():
    """Fixture for temporarily setting environment variables."""
    return TempEnv


# Utility functions for tests
def create_mock_response(status_code=200, data=None, headers=None):
    """Create a mock HTTP response with given status and data."""
    response = MagicMock()
    response.getcode = Mock(return_value=status_code)
    response.info = Mock(return_value=headers or {})
    response.read = Mock(return_value=json.dumps(data).encode() if data else b"")
    response.close = Mock()
    return response


def create_mock_urlopen(data, status_code=200):
    """Create a mock for urllib's urlopen."""
    response = create_mock_response(status_code=status_code, data=data)

    def mock_urlopen(*args, **kwargs):
        return response

    return mock_urlopen
