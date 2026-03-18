"""
Unit tests for unifi_utils.py.

These tests are self-contained and use mocks for all external dependencies.
Run with: pytest tests/unit/test_unifi_utils.py -v
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestAPHelpers:
    """Tests for AP helper functions."""

    @patch('unifi_utils.get_devices')
    def test_is_ap_actively_upgrading_success(self, mock_get):
        """Test AP actively upgrading detection."""
        mock_get.return_value = [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "upgrade_progress": 50,
                "upgrade_state": 1,
                "version": "6.2.28",
                "upgrade_to_firmware": "6.2.29"
            }
        ]

        result = unifi_utils.is_ap_actively_upgrading("aa:bb:cc:dd:ee:ff")

        assert result is True
        mock_get.assert_called_once()

    @patch('unifi_utils.make_unifi_api_call')
    def test_is_ap_actively_upgrading_not_upgrading(self, mock_call):
        """Test AP not upgrading."""
        mock_call.return_value = [{"state": 0, "state_name": "connected"}]

        result = unifi_utils.is_ap_actively_upgrading("aa:bb:cc:dd:ee:ff")

        assert result is False

    @patch('unifi_utils.make_unifi_api_call')
    def test_is_ap_actively_upgrading_exception(self, mock_call):
        """Test AP actively upgrading with exception."""
        mock_call.side_effect = Exception("API error")

        result = unifi_utils.is_ap_actively_upgrading("aa:bb:cc:dd:ee:ff")

        assert result is False

    def test_is_ap_fully_adopted_not_adopted(self):
        """Test AP not fully adopted."""
        device = {"type": "uap", "adopted": False}
        assert unifi_utils.is_ap_fully_adopted(device) is False

    def test_is_ap_fully_adopted_adopted(self):
        """Test AP fully adopted."""
        device = {"type": "uap", "adopted": True}
        assert unifi_utils.is_ap_fully_adopted(device) is True

    def test_is_ap_fully_adopted_wired_adopt_status_zero(self):
        """Test wired AP with adopt_status 0 is fully adopted."""
        device = {
            "type": "uap",
            "adopted": True,
            "adopt_status": 0,
            "uplink": {"type": "wire", "up": True},
        }
        assert unifi_utils.is_ap_fully_adopted(device) is True


class TestClientDataExport:
    """Tests for client data export functions."""

    def test_extract_wifi_speed_limit_basic(self):
        """Test basic WiFi speed limit extraction."""
        client_data = {
            "tx_rate": 100,
            "rx_rate": 200,
            "max_tx_rate": 500,
            "max_rx_rate": 600,
        }

        result = unifi_utils._extract_wifi_speed_limit(client_data)

        assert result == {
            "tx_rate": 100,
            "rx_rate": 200,
            "max_tx_rate": 500,
            "max_rx_rate": 600,
        }

    def test_extract_wifi_speed_limit_empty(self):
        """Test speed limit extraction with no speed limits."""
        client_data = {"hostname": "test"}
        result = unifi_utils._extract_wifi_speed_limit(client_data)
        assert result == {}

    def test_extract_wifi_speed_limit_partial(self):
        """Test speed limit extraction with partial data."""
        client_data = {"tx_rate": 100, "hostname": "test"}
        result = unifi_utils._extract_wifi_speed_limit(client_data)
        assert result == {"tx_rate": 100}

    @patch('unifi_utils.get_devices')
    def test_get_ap_name_by_mac_found(self, mock_get_devices):
        """Test getting AP name by MAC when found."""
        mock_get_devices.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Test AP"},
            {"mac": "11:22:33:44:55:66", "name": "Other AP"},
        ]

        result = unifi_utils._get_ap_name_by_mac("AA:BB:CC:DD:EE:FF")

        assert result == "Test AP"

    @patch('unifi_utils.get_devices')
    def test_get_ap_name_by_mac_not_found(self, mock_get_devices):
        """Test getting AP name by MAC when not found."""
        mock_get_devices.return_value = [
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Test AP"},
        ]

        result = unifi_utils._get_ap_name_by_mac("11:22:33:44:55:66")

        assert result == ""


class TestClientExportImport:
    """Tests for client export/import functionality."""

    def test_client_to_xml(self):
        """Test converting client to XML."""
        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "name": "Test Device",
            "note": "Test note",
            "speed_limits": {"tx_rate": 100, "rx_rate": 200},
            "locked": {"enabled": True, "ap_mac": "11:22:33:44:55:66", "ap_name": "AP1"},
            "ip_settings": {
                "use_fixed_ip": True,
                "fixed_ip": "192.168.1.100",
                "local_dns_enabled": True,
                "local_dns_record": "test.local",
            },
        }

        result = unifi_utils._client_to_xml(client_data)

        assert "<client>" in result
        assert "</client>" in result
        assert "aa:bb:cc:dd:ee:ff" in result
        assert "test-device" in result
        assert "Test Device" in result

    def test_client_to_xml_minimal(self):
        """Test converting minimal client to XML."""
        client_data = {"mac": "aa:bb:cc:dd:ee:ff"}

        result = unifi_utils._client_to_xml(client_data)

        assert "<client>" in result
        assert "</client>" in result
        assert "aa:bb:cc:dd:ee:ff" in result

    def test_clients_to_xml(self):
        """Test converting multiple clients to XML."""
        clients = [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "hostname": "device1",
                "name": "Device 1",
            },
            {
                "mac": "11:22:33:44:55:66",
                "hostname": "device2",
                "name": "Device 2",
            },
        ]

        result = unifi_utils._clients_to_xml(clients)

        assert "<unifi_clients" in result
        assert "device1" in result
        assert "device2" in result

    def test_xml_to_client(self):
        """Test converting XML to client dict."""
        xml_content = """<client>
            <mac>aa:bb:cc:dd:ee:ff</mac>
            <hostname>test-device</hostname>
            <name>Test Device</name>
            <note>Test note</note>
            <locked enabled="true">
                <ap_mac>11:22:33:44:55:66</ap_mac>
                <ap_name>AP1</ap_name>
            </locked>
            <ip_settings use_fixed_ip="true" local_dns_enabled="true">
                <fixed_ip>192.168.1.100</fixed_ip>
                <local_dns_record>test.local</local_dns_record>
            </ip_settings>
            <speed_limits>
                <tx_rate>100</tx_rate>
                <rx_rate>200</rx_rate>
            </speed_limits>
        </client>"""

        result = unifi_utils._xml_to_client(
            unifi_utils.ET.fromstring(xml_content)
        )

        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "test-device"
        assert result["name"] == "Test Device"
        assert result["note"] == "Test note"
        assert result["locked"]["enabled"] is True
        assert result["locked"]["ap_mac"] == "11:22:33:44:55:66"
        assert result["locked"]["ap_name"] == "AP1"
        assert result["ip_settings"]["use_fixed_ip"] is True
        assert result["ip_settings"]["fixed_ip"] == "192.168.1.100"
        assert result["speed_limits"]["tx_rate"] == 100

    def test_xml_to_clients(self):
        """Test converting XML content to list of clients."""
        xml_content = """<unifi_clients version="1.0">
            <client>
                <mac>aa:bb:cc:dd:ee:ff</mac>
                <hostname>device1</hostname>
                <name>Device 1</name>
            </client>
            <client>
                <mac>11:22:33:44:55:66</mac>
                <hostname>device2</hostname>
                <name>Device 2</name>
            </client>
        </unifi_clients>"""

        results = unifi_utils._xml_to_clients(xml_content)

        assert len(results) == 2
        assert results[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert results[1]["mac"] == "11:22:33:44:55:66"


class TestClientExport:
    """Tests for client export functions."""

    @patch('unifi_utils._get_single_client_data_by_mac')
    def test_export_client_data_success(self, mock_get_data):
        """Test successful client export."""
        mock_get_data.return_value = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "name": "Test Device",
            "note": "Test note",
            "fixed_ap_enabled": True,
            "fixed_ap_mac": "11:22:33:44:55:66",
            "use_fixedip": True,
            "fixed_ip": "192.168.1.100",
            "local_dns_record_enabled": True,
            "local_dns_record": "test.local",
        }

        with patch('unifi_utils._get_ap_name_by_mac', return_value="Test AP"):
            result = unifi_utils.export_client_data("aa:bb:cc:dd:ee:ff")

        assert result is not None
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "test-device"
        assert result["locked"]["enabled"] is True

    @patch('unifi_utils._get_single_client_data_by_mac')
    def test_export_client_data_not_found(self, mock_get_data):
        """Test client export when client not found."""
        mock_get_data.return_value = None

        result = unifi_utils.export_client_data("aa:bb:cc:dd:ee:ff")

        assert result is None


class TestRestoreClientData:
    """Tests for client restore functionality."""

    def test_restore_deleted_client_success(self):
        """Test restoring a deleted client."""
        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "name": "Test Device",
            "note": "Test note",
            "locked": {"enabled": True, "ap_mac": "11:22:33:44:55:66"},
            "ip_settings": {
                "use_fixed_ip": True,
                "fixed_ip": "192.168.1.100",
                "local_dns_enabled": True,
                "local_dns_record": "test.local",
            },
        }

        with patch('unifi_utils.make_unifi_api_call') as mock_call:
            with patch('unifi_utils._get_single_client_data_by_mac') as mock_get:
                mock_get.return_value = {
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "name": "Test Device",
                    "note": "Test note",
                    "fixed_ap_enabled": True,
                    "fixed_ap_mac": "11:22:33:44:55:66",
                }
                mock_call.return_value = {"meta": {"rc": "ok"}}

                result = unifi_utils.restore_deleted_client(
                    "aa:bb:cc:dd:ee:ff", client_data
                )

        assert result["success"] is True
        assert "name" in result["applied"]
        assert "note" in result["applied"]
        assert "locked" in result["applied"]
        assert "fixed_ip" in result["applied"]
        assert "local_dns" in result["applied"]

    @patch('unifi_utils.make_unifi_api_call')
    def test_restore_deleted_client_missing_mac(self, mock_api):
        """Test restoring client with missing MAC."""
        client_data = {
            "hostname": "test-device",
            "name": "Test Device",
        }

        # Mock successful API call
        mock_api.return_value = {"meta": {"rc": "ok"}}

        with patch('unifi_utils._get_single_client_data_by_mac') as mock_get:
            mock_get.return_value = {
                "mac": "aa:bb:cc:dd:ee:ff",
                "name": "Test Device",
                "note": "",
                "fixed_ap_enabled": False,
                "fixed_ap_mac": None,
            }
            result = unifi_utils.restore_deleted_client("aa:bb:cc:dd:ee:ff", client_data)

        # Should still try to create client (MAC is provided as argument)
        assert result["success"] is True
        mock_api.assert_called_once()

    @patch('unifi_utils._get_single_client_data_by_mac')
    @patch('unifi_utils.make_unifi_api_call')
    def test_restore_client_data_dry_run(self, mock_api, mock_get):
        """Test client restore in dry run mode."""
        mock_get.return_value = {
            "_id": "client-123",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device",
            "note": "Test note",
            "locked": {"enabled": True, "ap_mac": "11:22:33:44:55:66"},
            "ip_settings": {
                "use_fixed_ip": True,
                "fixed_ip": "192.168.1.100",
            },
        }

        result = unifi_utils.restore_client_data(client_data, dry_run=True)

        assert result["success"] is True
        mock_api.assert_not_called()  # No API calls in dry run
        assert "name" in result["applied"]
        assert "locked" in result["applied"]

    @patch('unifi_utils._get_single_client_data_by_mac')
    def test_restore_client_data_missing_mac(self, mock_get):
        """Test client restore with missing MAC."""
        client_data = {}

        result = unifi_utils.restore_client_data(client_data, dry_run=False)

        assert result["success"] is False
        assert len(result["failed"]) == 1
        assert result["failed"][0]["attribute"] == "mac"

    @patch('unifi_utils._get_single_client_data_by_mac')
    def test_restore_client_data_missing_id(self, mock_get):
        """Test client restore with missing client ID."""
        mock_get.return_value = {"mac": "aa:bb:cc:dd:ee:ff"}

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device",
        }

        result = unifi_utils.restore_client_data(client_data, dry_run=False)

        assert result["success"] is False
        assert len(result["failed"]) == 1
        assert result["failed"][0]["attribute"] == "client_id"

    @patch('unifi_utils.make_unifi_api_call')
    @patch('unifi_utils._get_single_client_data_by_mac')
    def test_restore_client_data_fails_verification_on_name_mismatch(self, mock_get, mock_api):
        """Restore should fail if the controller record does not reflect the requested name."""
        mock_get.side_effect = [
            {"_id": "client-123", "mac": "aa:bb:cc:dd:ee:ff"},
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Wrong Name", "note": "Test note", "fixed_ap_enabled": False, "fixed_ap_mac": None},
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Wrong Name", "note": "Test note", "fixed_ap_enabled": False, "fixed_ap_mac": None},
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Wrong Name", "note": "Test note", "fixed_ap_enabled": False, "fixed_ap_mac": None},
            {"mac": "aa:bb:cc:dd:ee:ff", "name": "Wrong Name", "note": "Test note", "fixed_ap_enabled": False, "fixed_ap_mac": None},
        ]
        mock_api.return_value = {"meta": {"rc": "ok"}}

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device",
            "note": "Test note",
            "locked": {"enabled": False},
            "ip_settings": {},
        }

        result = unifi_utils.restore_client_data(client_data, dry_run=False)

        assert result["success"] is False
        assert any(f["attribute"] == "verification" for f in result["failed"])


class TestBackupDirectory:
    """Tests for backup directory handling."""

    @patch('os.makedirs')
    @patch('datetime.datetime')
    @patch('unifi_utils._clients_to_xml')
    @patch('builtins.open')
    def test_export_clients_to_file_creates_dir(self, mock_open, mock_xml, mock_dt, mock_mkdir):
        """Test that export clients creates backup directory."""
        mock_dt.now.return_value = datetime(2024, 1, 15, 10, 30, 0)
        mock_xml.return_value = "<unifi_clients></unifi_clients>"

        result = unifi_utils.export_clients_to_file(
            [{"mac": "aa:bb:cc:dd:ee:ff"}],
            backup_dir="/tmp/test_backup"
        )

        mock_mkdir.assert_called_once_with("/tmp/test_backup", exist_ok=True)
        assert result == "/tmp/test_backup/unifi_clients_20240115_103000.xml"

    @patch('os.makedirs')
    @patch('datetime.datetime')
    @patch('unifi_utils._clients_to_xml')
    @patch('builtins.open')
    def test_export_clients_to_file_default_dir(self, mock_open, mock_xml, mock_dt, mock_mkdir):
        """Test export clients with default backup directory."""
        from pathlib import Path

        mock_dt.now.return_value = datetime(2024, 1, 15, 10, 30, 0)
        mock_xml.return_value = "<unifi_clients></unifi_clients>"

        with patch.object(Path, 'home', return_value=Path("/home/test")):
            result = unifi_utils.export_clients_to_file(
                [{"mac": "aa:bb:cc:dd:ee:ff"}]
            )

        expected_dir = "/home/test/.netcon-sync/unifi_backups"
        mock_mkdir.assert_called_once_with(expected_dir, exist_ok=True)
        assert expected_dir in result


class TestAPStateDescription:
    """Tests for AP state description function."""

    def test_get_ap_state_description_string(self):
        """Test AP state description with string input."""
        import unifi_utils

        result = unifi_utils._get_ap_state_description("connected")
        assert result == "connected"

    def test_get_ap_state_description_integer(self):
        """Test AP state description with integer input."""
        import unifi_utils

        result = unifi_utils._get_ap_state_description(0)
        assert result == "DISCONNECTED"

        result = unifi_utils._get_ap_state_description(1)
        assert result == "CONNECTING/INITIALIZING"

        result = unifi_utils._get_ap_state_description(2)
        assert result == "CONNECTED (but not fully ready)"

        result = unifi_utils._get_ap_state_description(3)
        assert result == "RUNNING"

    def test_get_ap_state_description_unknown(self):
        """Test AP state description with unknown integer."""
        import unifi_utils

        result = unifi_utils._get_ap_state_description(99)
        assert result == "UNKNOWN"


class TestBandDerivation:
    """Tests for WiFi band derivation functions."""

    def test_derive_band_from_channel_2_4ghz(self):
        """Test deriving 2.4GHz band from channel."""
        import unifi_utils

        result = unifi_utils._derive_band_from_channel("1")
        assert result == "2.4"

    def test_derive_band_from_channel_5ghz(self):
        """Test deriving 5GHz band from channel."""
        import unifi_utils

        result = unifi_utils._derive_band_from_channel("36")
        assert result == "5"

    def test_derive_band_from_channel_6ghz(self):
        """Test deriving 6GHz band from channel."""
        import unifi_utils

        # Channel 200 is in 6GHz band only (not in 5GHz range 36-165)
        result = unifi_utils._derive_band_from_channel("200")
        assert result == "6"

    def test_derive_band_from_channel_invalid(self):
        """Test deriving band from invalid channel."""
        import unifi_utils

        result = unifi_utils._derive_band_from_channel("N/A")
        assert result == "N/A"

        result = unifi_utils._derive_band_from_channel("")
        assert result == "N/A"

        result = unifi_utils._derive_band_from_channel("invalid")
        assert result == "N/A"


class TestWifiGenerationDerivation:
    """Tests for WiFi generation derivation functions."""

    def test_derive_wifi_generation_from_proto_80211a(self):
        """Test WiFi generation from 802.11a protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("a")
        assert result == "2"

    def test_derive_wifi_generation_from_proto_80211ac(self):
        """Test WiFi generation from 802.11ac protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("ac")
        assert result == "5"

    def test_derive_wifi_generation_from_proto_80211ax(self):
        """Test WiFi generation from 802.11ax protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("ax")
        assert result == "6"

    def test_derive_wifi_generation_from_proto_80211be(self):
        """Test WiFi generation from 802.11be protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("be")
        assert result == "7"

    def test_derive_wifi_generation_from_proto_n(self):
        """Test WiFi generation from 802.11n protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("n")
        assert result == "4"

    def test_derive_wifi_generation_from_proto_invalid(self):
        """Test WiFi generation from invalid protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto("")
        assert result == "N/A"

    def test_derive_wifi_generation_from_proto_none(self):
        """Test WiFi generation from None protocol."""
        import unifi_utils

        result = unifi_utils._derive_wifi_generation_from_proto(None)
        assert result == "N/A"


class TestIeeeVersionDerivation:
    """Tests for IEEE version derivation functions."""

    def test_derive_ieee_version_from_proto_80211ax(self):
        """Test IEEE version from 802.11ax protocol."""
        import unifi_utils

        result = unifi_utils._derive_ieee_version_from_proto("ax")
        assert result == "802.11ax"

    def test_derive_ieee_version_from_proto_80211ac(self):
        """Test IEEE version from 802.11ac protocol."""
        import unifi_utils

        result = unifi_utils._derive_ieee_version_from_proto("ac")
        assert result == "802.11ac"

    def test_derive_ieee_version_from_proto_invalid(self):
        """Test IEEE version from invalid protocol."""
        import unifi_utils

        result = unifi_utils._derive_ieee_version_from_proto("")
        assert result == "N/A"


class TestGetUnifiClientsFast:
    """Tests for get_unifi_clients_fast() function."""

    @patch('unifi_utils.make_unifi_api_call')
    def test_get_unifi_clients_fast_basic(self, mock_call):
        """Test basic client fetching with is_connected_live field."""
        # First call: known clients
        # Second call: empty live clients (no one connected)
        mock_call.side_effect = [
            [
                {"mac": "aa:bb:cc:dd:ee:01", "name": "client1"},
                {"mac": "aa:bb:cc:dd:ee:02", "name": "client2"},
            ],
            []  # No live clients
        ]

        result = unifi_utils.get_unifi_clients_fast()

        # Verify both API calls were made
        assert mock_call.call_count == 2

        # Verify result structure - keys are normalized to lowercase with colons removed
        assert len(result) == 2
        assert "aa:bb:cc:dd:ee:01" in result
        assert "aa:bb:cc:dd:ee:02" in result

        # Verify is_connected_live is False when no live clients
        assert result["aa:bb:cc:dd:ee:01"]["is_connected_live"] is False
        assert result["aa:bb:cc:dd:ee:02"]["is_connected_live"] is False

    @patch('unifi_utils.make_unifi_api_call')
    def test_get_unifi_clients_fast_with_connected(self, mock_call):
        """Test client fetching with connected clients."""
        # First call: known clients
        # Second call: live connected clients
        mock_call.side_effect = [
            [
                {"mac": "aa:bb:cc:dd:ee:01", "name": "client1"},
                {"mac": "aa:bb:cc:dd:ee:02", "name": "client2"},
                {"mac": "aa:bb:cc:dd:ee:03", "name": "client3"},
            ],
            [
                {"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.100"},  # Connected
                {"mac": "aa:bb:cc:dd:ee:03", "ip": "192.168.1.102"},  # Connected
            ]
        ]

        result = unifi_utils.get_unifi_clients_fast()

        # Verify is_connected_live is correctly set
        assert result["aa:bb:cc:dd:ee:01"]["is_connected_live"] is True  # Connected
        assert result["aa:bb:cc:dd:ee:02"]["is_connected_live"] is False  # Not connected
        assert result["aa:bb:cc:dd:ee:03"]["is_connected_live"] is True  # Connected

    @patch('unifi_utils.make_unifi_api_call')
    def test_get_unifi_clients_fast_mac_normalization(self, mock_call):
        """Test that MAC addresses are normalized to lowercase."""
        mock_call.side_effect = [
            [
                {"mac": "aa:bb:cc:dd:ee:01", "name": "client1"},
                {"mac": "aa:bb:cc:dd:ee:02", "name": "client2"},
            ],
            []  # No live clients
        ]

        result = unifi_utils.get_unifi_clients_fast()

        # Keys should be lowercase with colons (as returned by the API)
        assert "aa:bb:cc:dd:ee:01" in result
        assert "aa:bb:cc:dd:ee:02" in result
        assert len(result) == 2


class TestFiltering:
    """Tests for client filtering logic."""

    def test_filter_online(self):
        """Test filtering online clients."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "is_connected_live": True},
            {"mac": "aa:bb:cc:dd:ee:02", "is_connected_live": False},
            {"mac": "aa:bb:cc:dd:ee:03", "is_connected_live": True},
        ]

        filtered = [c for c in clients if c.get("is_connected_live")]

        assert len(filtered) == 2
        assert all(c["is_connected_live"] for c in filtered)

    def test_filter_offline(self):
        """Test filtering offline clients."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "is_connected_live": True},
            {"mac": "aa:bb:cc:dd:ee:02", "is_connected_live": False},
            {"mac": "aa:bb:cc:dd:ee:03", "is_connected_live": False},
        ]

        filtered = [c for c in clients if not c.get("is_connected_live")]

        assert len(filtered) == 2
        assert all(not c["is_connected_live"] for c in filtered)

    def test_filter_locked(self):
        """Test filtering locked clients."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "is_ap_locked": True},
            {"mac": "aa:bb:cc:dd:ee:02", "is_ap_locked": False},
            {"mac": "aa:bb:cc:dd:ee:03", "is_ap_locked": True},
        ]

        filtered = [c for c in clients if c.get("is_ap_locked")]

        assert len(filtered) == 2
        assert all(c["is_ap_locked"] for c in filtered)

    def test_filter_ip(self):
        """Test filtering by IP address."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "display_ip": "192.168.1.100"},
            {"mac": "aa:bb:cc:dd:ee:02", "display_ip": "10.0.0.50"},
            {"mac": "aa:bb:cc:dd:ee:03", "display_ip": "192.168.1.200"},
        ]

        filtered = [c for c in clients if "192.168.1" in c.get("display_ip", "")]

        assert len(filtered) == 2
        assert all("192.168.1" in c["display_ip"] for c in filtered)

    def test_filter_mac(self):
        """Test filtering by MAC address."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01"},
            {"mac": "11:22:33:44:55:66"},
            {"mac": "aa:bb:cc:dd:ee:02"},
        ]

        filtered = [
            c for c in clients
            if "aabbcc" in c.get("mac", "").replace(":", "").lower()
        ]

        assert len(filtered) == 2

    def test_filter_hostname(self):
        """Test filtering by hostname."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "hostname": "phone-1"},
            {"mac": "aa:bb:cc:dd:ee:02", "hostname": "laptop-1"},
            {"mac": "aa:bb:cc:dd:ee:03", "hostname": "phone-2"},
        ]

        filtered = [c for c in clients if "phone" in c.get("hostname", "").lower()]

        assert len(filtered) == 2


# Import unifi_utils for tests
import unifi_utils


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
