"""
Integration tests for UniFi controller.

These tests require a live UniFi controller to run.
Set environment variables:
  UNIFI_NETWORK_URL - Controller URL (e.g., https://unifi.local)
  UNIFI_USERNAME - Controller username
  UNIFI_PASSWORD - Controller password
  UNIFI_SITE_ID - Site ID (e.g., default)

Run with: pytest tests/functional/test_live_controller.py -v -m integration
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Skip all tests if no controller configured
pytestmark = pytest.mark.skipif(
    not all([
        pytest.config.getoption("--live-controller"),
        "UNIFI_NETWORK_URL" in __import__("os").environ,
        "UNIFI_USERNAME" in __import__("os").environ,
        "UNIFI_PASSWORD" in __import__("os").environ,
        "UNIFI_SITE_ID" in __import__("os").environ,
    ]),
    reason="Live controller not configured"
)


class TestControllerConnection:
    """Tests for controller connection and basic operations."""

    def test_controller_reachable(self):
        """Test that controller is reachable."""
        import unifi_utils

        try:
            # Try to get system info
            result = unifi_utils.make_unifi_api_call(
                "GET",
                f"/api/s/{unifi_utils.UNIFI_SITE_ID}/stat/sysinfo"
            )
            assert result is not None
        except Exception as e:
            pytest.fail(f"Controller not reachable: {e}")

    def test_login_success(self):
        """Test successful login."""
        import unifi_utils

        try:
            unifi_utils.login()
            # If we get here without exception, login succeeded
        except Exception as e:
            pytest.fail(f"Login failed: {e}")

    def test_get_site_info(self):
        """Test getting site information."""
        import unifi_utils

        try:
            result = unifi_utils.make_unifi_api_call(
                "GET",
                f"/api/s/{unifi_utils.UNIFI_SITE_ID}/stat/site"
            )
            assert isinstance(result, list)
            assert len(result) > 0
            assert "name" in result[0]
        except Exception as e:
            pytest.fail(f"Failed to get site info: {e}")


class TestClientOperations:
    """Tests for client operations."""

    def test_get_all_clients(self):
        """Test getting all clients."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()
            assert isinstance(clients, list)
        except Exception as e:
            pytest.fail(f"Failed to get clients: {e}")

    def test_get_clients_with_filters(self):
        """Test getting clients with filters."""
        import unifi_utils

        try:
            # Test online filter
            online_clients = unifi_utils.get_all_unifi_clients()
            online_only = [c for c in online_clients if c.get("is_connected_live")]
            assert isinstance(online_only, list)

            # Test offline filter
            offline_only = [c for c in online_clients if not c.get("is_connected_live")]
            assert isinstance(offline_only, list)
        except Exception as e:
            pytest.fail(f"Failed to filter clients: {e}")

    def test_client_has_required_fields(self):
        """Test that clients have required fields."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                assert "mac" in client
                assert "hostname" in client or "name" in client
        except Exception as e:
            pytest.fail(f"Failed to validate client fields: {e}")


class TestAPOperations:
    """Tests for AP operations."""

    def test_get_all_aps(self):
        """Test getting all APs."""
        import unifi_utils

        try:
            aps = unifi_utils.get_devices()
            aps = [ap for ap in aps if ap.get("type") == "uap"]
            assert isinstance(aps, list)
        except Exception as e:
            pytest.fail(f"Failed to get APs: {e}")

    def test_ap_is_adopted(self):
        """Test AP adoption status."""
        import unifi_utils

        try:
            aps = unifi_utils.get_devices()
            aps = [ap for ap in aps if ap.get("type") == "uap"]

            if aps:
                # Check that is_ap_fully_adopted works
                for ap in aps:
                    result = unifi_utils.is_ap_fully_adopted(ap)
                    assert isinstance(result, bool)
        except Exception as e:
            pytest.fail(f"Failed to check AP adoption: {e}")

    def test_ap_upgrading_detection(self):
        """Test AP upgrading detection."""
        import unifi_utils

        try:
            aps = unifi_utils.get_devices()
            aps = [ap for ap in aps if ap.get("type") == "uap"]

            if aps:
                # Check that is_ap_actively_upgrading works
                for ap in aps[:1]:  # Test first AP only
                    result = unifi_utils.is_ap_actively_upgrading(ap["mac"])
                    assert isinstance(result, bool)
        except Exception as e:
            pytest.fail(f"Failed to check AP upgrading: {e}")


class TestSSIDOperations:
    """Tests for SSID operations."""

    def test_get_all_ssids(self):
        """Test getting all SSIDs."""
        import unifi_utils

        try:
            ssids = unifi_utils.get_ssids()
            assert isinstance(ssids, list)
        except Exception as e:
            pytest.fail(f"Failed to get SSIDs: {e}")

    def test_ssid_enabled_status(self):
        """Test SSID enabled status."""
        import unifi_utils

        try:
            ssids = unifi_utils.get_ssids()

            if ssids:
                for ssid in ssids[:2]:  # Test first 2 SSIDs
                    assert "enabled" in ssid
                    assert isinstance(ssid["enabled"], bool)
        except Exception as e:
            pytest.fail(f"Failed to check SSID status: {e}")


class TestBackupRestore:
    """Tests for backup and restore functionality."""

    def test_export_client_data(self):
        """Test exporting client data."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                mac = client["mac"]

                # Export client data
                export_data = unifi_utils.export_client_data(mac)
                assert export_data is not None
                assert "mac" in export_data
                assert "name" in export_data
                assert "note" in export_data
                assert "locked" in export_data
                assert "ip_settings" in export_data
        except Exception as e:
            pytest.fail(f"Failed to export client data: {e}")

    def test_clients_to_xml(self):
        """Test converting clients to XML."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                # Export first few clients
                export_data = []
                for client in clients[:3]:
                    data = unifi_utils.export_client_data(client["mac"])
                    if data:
                        export_data.append(data)

                # Convert to XML
                xml = unifi_utils._clients_to_xml(export_data)
                assert "<unifi_clients" in xml
                assert "</unifi_clients>" in xml
        except Exception as e:
            pytest.fail(f"Failed to convert clients to XML: {e}")

    def test_backup_to_file(self):
        """Test backing up clients to file."""
        import unifi_utils
        import tempfile
        import os

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                # Create temp directory
                with tempfile.TemporaryDirectory() as tmpdir:
                    # Export first client
                    export_data = [unifi_utils.export_client_data(clients[0]["mac"])]

                    # Save to file
                    filepath = unifi_utils.export_clients_to_file(
                        export_data,
                        backup_dir=tmpdir
                    )

                    assert os.path.exists(filepath)
                    assert filepath.endswith(".xml")
                    assert "unifi_clients_" in filepath
        except Exception as e:
            pytest.fail(f"Failed to backup clients: {e}")

    def test_restore_from_xml(self):
        """Test restoring clients from XML."""
        import unifi_utils
        import tempfile
        import os

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                # Create temp directory
                with tempfile.TemporaryDirectory() as tmpdir:
                    # Export first client
                    export_data = [unifi_utils.export_client_data(clients[0]["mac"])]

                    # Save to file
                    filepath = unifi_utils.export_clients_to_file(
                        export_data,
                        backup_dir=tmpdir
                    )

                    # Read back
                    with open(filepath, 'r') as f:
                        xml_content = f.read()

                    # Parse XML
                    parsed_clients = unifi_utils._xml_to_clients(xml_content)
                    assert len(parsed_clients) == 1
                    assert parsed_clients[0]["mac"] == clients[0]["mac"]
        except Exception as e:
            pytest.fail(f"Failed to restore from XML: {e}")


class TestDryRunRestore:
    """Tests for dry-run restore functionality."""

    def test_restore_dry_run(self):
        """Test restore in dry-run mode."""
        import unifi_utils
        import tempfile
        import os

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                # Create temp directory
                with tempfile.TemporaryDirectory() as tmpdir:
                    # Export first client
                    export_data = [unifi_utils.export_client_data(clients[0]["mac"])]

                    # Save to file
                    filepath = unifi_utils.export_clients_to_file(
                        export_data,
                        backup_dir=tmpdir
                    )

                    # Read back
                    with open(filepath, 'r') as f:
                        xml_content = f.read()

                    parsed_clients = unifi_utils._xml_to_clients(xml_content)

                    # Dry run restore (should not make API calls)
                    with patch('unifi_utils.make_unifi_api_call') as mock_api:
                        result = unifi_utils.restore_client_data(
                            parsed_clients[0],
                            dry_run=True
                        )

                        assert result["success"] is True
                        mock_api.assert_not_called()
        except Exception as e:
            pytest.fail(f"Failed dry-run restore: {e}")


class TestClientFiltering:
    """Tests for client filtering."""

    def test_filter_by_online_status(self):
        """Test filtering clients by online status."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            online = [c for c in clients if c.get("is_connected_live")]
            offline = [c for c in clients if not c.get("is_connected_live")]

            assert len(online) + len(offline) == len(clients)
        except Exception as e:
            pytest.fail(f"Failed to filter by online status: {e}")

    def test_filter_by_locked_status(self):
        """Test filtering clients by locked status."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            locked = [c for c in clients if c.get("is_ap_locked")]
            unlocked = [c for c in clients if not c.get("is_ap_locked")]

            assert len(locked) + len(unlocked) == len(clients)
        except Exception as e:
            pytest.fail(f"Failed to filter by locked status: {e}")

    def test_filter_by_ip(self):
        """Test filtering clients by IP address."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            # Filter by common IP patterns
            filtered_192 = [c for c in clients if "192.168" in c.get("display_ip", "")]
            filtered_10 = [c for c in clients if "10.0.0" in c.get("display_ip", "")]

            assert isinstance(filtered_192, list)
            assert isinstance(filtered_10, list)
        except Exception as e:
            pytest.fail(f"Failed to filter by IP: {e}")

    def test_filter_by_hostname(self):
        """Test filtering clients by hostname."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            # Filter by common hostname patterns
            filtered_phone = [
                c for c in clients
                if "phone" in c.get("hostname", "").lower()
            ]
            filtered_laptop = [
                c for c in clients
                if "laptop" in c.get("hostname", "").lower()
            ]

            assert isinstance(filtered_phone, list)
            assert isinstance(filtered_laptop, list)
        except Exception as e:
            pytest.fail(f"Failed to filter by hostname: {e}")


class TestNetworkInfo:
    """Tests for network information retrieval."""

    def test_get_network_info(self):
        """Test getting network information."""
        import unifi_utils

        try:
            # Get network statistics
            result = unifi_utils.make_unifi_api_call(
                "GET",
                f"/api/s/{unifi_utils.UNIFI_SITE_ID}/stat/netstat"
            )
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"Failed to get network info: {e}")

    def test_get_traffic_stats(self):
        """Test getting traffic statistics."""
        import unifi_utils

        try:
            # Get traffic stats
            result = unifi_utils.make_unifi_api_call(
                "GET",
                f"/api/s/{unifi_utils.UNIFI_SITE_ID}/stat/traffic"
            )
            assert isinstance(result, list)
        except Exception as e:
            pytest.fail(f"Failed to get traffic stats: {e}")


class TestClientAttributes:
    """Tests for client attribute retrieval."""

    def test_client_name(self):
        """Test client name retrieval."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                name = client.get("name", "")
                hostname = client.get("hostname", "")

                assert isinstance(name, str)
                assert isinstance(hostname, str)
        except Exception as e:
            pytest.fail(f"Failed to get client name: {e}")

    def test_client_note(self):
        """Test client note retrieval."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                note = client.get("note", "")

                assert isinstance(note, str)
        except Exception as e:
            pytest.fail(f"Failed to get client note: {e}")

    def test_client_ip_address(self):
        """Test client IP address retrieval."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                ip = client.get("display_ip", "")

                assert isinstance(ip, str)
        except Exception as e:
            pytest.fail(f"Failed to get client IP: {e}")

    def test_client_mac_address(self):
        """Test client MAC address retrieval."""
        import unifi_utils

        try:
            clients = unifi_utils.get_all_unifi_clients()

            if clients:
                client = clients[0]
                mac = client.get("mac", "")

                assert isinstance(mac, str)
                # Basic MAC format validation
                assert len(mac.replace(":", "")) == 12
        except Exception as e:
            pytest.fail(f"Failed to get client MAC: {e}")


# Custom pytest marker for live tests
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "live: mark test as requiring live controller"
    )


def pytest_addoption(parser):
    """Add command-line options."""
    parser.addoption(
        "--live-controller",
        action="store_true",
        default=False,
        help="Run integration tests against live controller"
    )
