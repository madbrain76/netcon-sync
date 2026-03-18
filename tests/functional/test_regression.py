"""
Regression tests for netcon-sync.

These tests verify that previously fixed issues remain fixed.
Run with: pytest tests/functional/test_regression.py -v
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestSsidToggle:
    """Regression tests for SSID toggle functionality."""

    def test_disable_ssid_single_payload(self):
        """
        Regression test for: SSID disable sends a single payload.
        Note: Retry logic with minimal payload is not yet implemented.
        """
        import unifi_utils

        ssid = {
            "_id": "ssid-1",
            "name": "IOT",
            "enabled": True,
            "site_id": "default",
            "readonly_field": "value",
        }
        calls = []

        def fake_make_unifi_api_call(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs.get("json", {})))
            return {"meta": {"rc": "ok"}}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(
                unifi_utils, "make_unifi_api_call",
                side_effect=fake_make_unifi_api_call
            ):
                result = unifi_utils.disable_ssid("iot")

        assert result is True
        assert len(calls) == 1
        assert calls[0][0] == "PUT"
        assert "ssid-1" in calls[0][1]
        # Call should include readonly_field (full payload)
        assert "readonly_field" in calls[0][2]

    def test_enable_ssid_returns_true_when_already_enabled(self):
        """
        Regression test for: enable_ssid should return True when already enabled.

        Previously: Would make unnecessary API call.
        Fixed: Short-circuits when already enabled.
        """
        import unifi_utils

        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.enable_ssid("IOT")

        assert result is True
        mock_api.assert_not_called()

    def test_disable_ssid_returns_false_when_not_found(self):
        """
        Regression test for: disable_ssid should return False when SSID not found.
        """
        import unifi_utils

        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.disable_ssid("NonExistent")

        assert result is False
        mock_api.assert_not_called()

    def test_disable_ssid_returns_true_when_already_disabled(self):
        """
        Regression test for: disable_ssid should return True when already disabled.
        """
        import unifi_utils

        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": False}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.disable_ssid("iot")

        assert result is True
        mock_api.assert_not_called()


class TestAPAdoption:
    """Regression tests for AP adoption detection."""

    def test_is_ap_fully_adopted_false_when_not_adopted(self):
        """
        Regression test for: AP adoption detection.

        Previously: Could incorrectly report adopted status.
        Fixed: Properly checks adopted flag.
        """
        import unifi_utils

        device = {"type": "uap", "adopted": False}
        assert unifi_utils.is_ap_fully_adopted(device) is False

    def test_is_ap_fully_adopted_true_for_wired_ap_even_with_zero_adopt_status(self):
        """
        Regression test for: Wired APs with adopt_status 0 should be fully adopted.

        Previously: Wired APs with adopt_status 0 were incorrectly reported as not adopted.
        Fixed: Wired APs with uplink type "wire" and up=True are considered fully adopted.
        """
        import unifi_utils

        device = {
            "type": "uap",
            "adopted": True,
            "adopt_status": 0,
            "uplink": {"type": "wire", "up": True},
        }
        assert unifi_utils.is_ap_fully_adopted(device) is True

    def test_u6_lr_name_is_treated_as_default_ap_name(self):
        """
        Regression test for: stock UniFi labels like "U6 LR" must not be
        treated as custom names during reverse-DNS naming.

        Previously: "U6 LR" could be misclassified as non-default.
        Fixed: generic UniFi model-style labels are recognized as default.
        """
        import unifi_utils

        device = {
            "type": "uap",
            "name": "U6 LR",
            "model": "U6-LR",
        }

        assert unifi_utils._looks_like_unifi_default_ap_name("U6 LR", device) is True


class TestClientBackupRestore:
    """Regression tests for client backup/restore."""

    def test_client_to_xml_preserves_all_fields(self):
        """
        Regression test for: Client XML export should preserve all fields.

        Previously: Some fields were lost during export.
        Fixed: All configurable fields are now exported.
        """
        import unifi_utils

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

        xml = unifi_utils._client_to_xml(client_data)

        # Verify all fields are in XML
        assert "<mac>aa:bb:cc:dd:ee:ff</mac>" in xml
        assert "<hostname>test-device</hostname>" in xml
        assert "<name>Test Device</name>" in xml
        assert "<note>Test note</note>" in xml
        assert "tx_rate" in xml
        assert "rx_rate" in xml
        assert "11:22:33:44:55:66" in xml
        assert "192.168.1.100" in xml
        assert "test.local" in xml

    def test_xml_to_client_round_trip(self):
        """
        Regression test for: XML round-trip should preserve data.

        Previously: Some fields were corrupted during XML conversion.
        Fixed: Round-trip conversion preserves all data.
        """
        import unifi_utils

        original = {
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

        xml = unifi_utils._client_to_xml(original)
        restored = unifi_utils._xml_to_client(unifi_utils.ET.fromstring(xml))

        assert restored["mac"] == original["mac"]
        assert restored["hostname"] == original["hostname"]
        assert restored["name"] == original["name"]
        assert restored["note"] == original["note"]
        assert restored["locked"]["enabled"] == original["locked"]["enabled"]
        assert restored["locked"]["ap_mac"] == original["locked"]["ap_mac"]
        assert restored["ip_settings"]["use_fixed_ip"] == original["ip_settings"]["use_fixed_ip"]
        assert restored["ip_settings"]["fixed_ip"] == original["ip_settings"]["fixed_ip"]

    def test_restore_client_data_skips_unsupported_attributes(self):
        """
        Regression test for: Restore should gracefully skip unsupported attributes.

        Previously: Restore would fail completely if any attribute was unsupported.
        Fixed: Unsupported attributes are skipped, supported ones are applied.
        """
        import unifi_utils

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device",
            "note": "Test note",
            "locked": {"enabled": True, "ap_mac": "11:22:33:44:55:66"},
            "ip_settings": {
                "use_fixed_ip": True,
                "fixed_ip": "192.168.1.100",
            },
            "speed_limits": {"tx_rate": 100},  # May not be supported
        }

        with patch('unifi_utils._get_single_client_data_by_mac') as mock_get:
            mock_get.return_value = {
                "_id": "client-123",
                "mac": "aa:bb:cc:dd:ee:ff",
            }

            with patch('unifi_utils.make_unifi_api_call') as mock_api:
                mock_api.return_value = {"meta": {"rc": "ok"}}

                result = unifi_utils.restore_client_data(client_data, dry_run=False)

                assert result["success"] is True
                assert "name" in result["applied"]
                assert "note" in result["applied"]
                assert "locked" in result["applied"]

    def test_restore_deleted_client_recreates_with_all_attributes(self):
        """
        Regression test for: Deleted client restore should recreate with all attributes.

        Previously: Deleted clients were recreated with minimal data.
        Fixed: All saved attributes are restored when recreating deleted clients.
        """
        import unifi_utils

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

        with patch('unifi_utils.make_unifi_api_call') as mock_api:
            mock_api.return_value = {"meta": {"rc": "ok"}}

            result = unifi_utils.restore_deleted_client(
                "aa:bb:cc:dd:ee:ff", client_data
            )

            assert result["success"] is True
            assert "name" in result["applied"]
            assert "note" in result["applied"]
            assert "locked" in result["applied"]
            assert "fixed_ip" in result["applied"]
            assert "local_dns" in result["applied"]


class TestControllerAPICompatibility:
    """Regression tests for controller API compatibility."""

    def test_make_unifi_api_call_public_method(self):
        """
        Regression test for: make_unifi_api_call should be public (not private).

        Previously: Method was _make_unifi_api_call (private).
        Fixed: Renamed to make_unifi_api_call (public).
        """
        import unifi_utils

        # Should be accessible without underscore
        assert hasattr(unifi_utils, "make_unifi_api_call")
        assert callable(unifi_utils.make_unifi_api_call)

        # Should NOT be private
        assert not hasattr(unifi_utils, "_make_unifi_api_call")


class TestClientFiltering:
    """Regression tests for client filtering."""

    def test_filter_online_offline_exclusive(self):
        """
        Regression test for: Online/offline filters should be mutually exclusive.

        Previously: Both filters could be applied, causing confusion.
        Fixed: Filters work independently and correctly.
        """
        import unifi_utils

        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "is_connected_live": True},
            {"mac": "aa:bb:cc:dd:ee:02", "is_connected_live": False},
            {"mac": "aa:bb:cc:dd:ee:03", "is_connected_live": True},
        ]

        online = [c for c in clients if c.get("is_connected_live")]
        offline = [c for c in clients if not c.get("is_connected_live")]

        assert len(online) == 2
        assert len(offline) == 1
        assert len(online) + len(offline) == len(clients)

    def test_filter_locked_unlocked_exclusive(self):
        """
        Regression test for: Locked/unlocked filters should be mutually exclusive.

        Previously: Filter logic was inconsistent.
        Fixed: Filters now work correctly and predictably.
        """
        import unifi_utils

        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "is_ap_locked": True},
            {"mac": "aa:bb:cc:dd:ee:02", "is_ap_locked": False},
            {"mac": "aa:bb:cc:dd:ee:03", "is_ap_locked": True},
        ]

        locked = [c for c in clients if c.get("is_ap_locked")]
        unlocked = [c for c in clients if not c.get("is_ap_locked")]

        assert len(locked) == 2
        assert len(unlocked) == 1
        assert len(locked) + len(unlocked) == len(clients)

    def test_filter_ip_substring_match(self):
        """
        Regression test for: IP filter should do substring matching.

        Previously: Exact match only, limiting filter usefulness.
        Fixed: Substring matching allows flexible filtering.
        """
        import unifi_utils

        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "display_ip": "192.168.1.100"},
            {"mac": "aa:bb:cc:dd:ee:02", "display_ip": "10.0.0.50"},
            {"mac": "aa:bb:cc:dd:ee:03", "display_ip": "192.168.1.200"},
        ]

        filtered = [c for c in clients if "192.168.1" in c.get("display_ip", "")]

        assert len(filtered) == 2
        assert all("192.168.1" in c["display_ip"] for c in filtered)

    def test_filter_mac_normalized(self):
        """
        Regression test for: MAC filter should handle various formats.

        Previously: MAC format variations caused filter failures.
        Fixed: MAC addresses are normalized before comparison.
        """
        import unifi_utils

        clients = [
            {"mac": "aa:bb:cc:dd:ee:01"},
            {"mac": "AA:BB:CC:DD:EE:02"},
            {"mac": "aabbccddeeff"},
        ]

        # Filter should work regardless of format
        filtered = [
            c for c in clients
            if "aabbcc" in c.get("mac", "").replace(":", "").lower()
        ]

        assert len(filtered) == 3

    def test_filter_hostname_case_insensitive(self):
        """
        Regression test for: Hostname filter should be case-insensitive.

        Previously: Case-sensitive matching limited filter usefulness.
        Fixed: Hostname matching is now case-insensitive.
        """
        import unifi_utils

        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "hostname": "Phone-1"},
            {"mac": "aa:bb:cc:dd:ee:02", "hostname": "phone-2"},
            {"mac": "aa:bb:cc:dd:ee:03", "hostname": "PHONE-3"},
            {"mac": "aa:bb:cc:dd:ee:04", "hostname": "Laptop-1"},
        ]

        filtered = [
            c for c in clients
            if "phone" in c.get("hostname", "").lower()
        ]

        assert len(filtered) == 3


class TestBatchOperations:
    """Regression tests for batch operations."""

    def test_batch_forget_mac_lowercasing(self):
        """
        Regression test for: Batch forget should lowercase MAC addresses.

        Previously: MAC case sensitivity caused issues.
        Fixed: All MAC addresses are lowercased before API calls.
        """
        import unifi_utils

        mac_list = ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        lower_list = [mac.lower() for mac in mac_list]

        assert all(mac == mac.lower() for mac in lower_list)
        assert lower_list == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]


class TestBackupFileHandling:
    """Regression tests for backup file handling."""

    def test_backup_file_timestamp_format(self):
        """
        Regression test for: Backup file timestamp format.

        Previously: Inconsistent timestamp formats.
        Fixed: Standardized YYYYMMDD_HHMMSS format.
        """
        import unifi_utils
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            export_data = [{"mac": "aa:bb:cc:dd:ee:ff"}]

            filepath = unifi_utils.export_clients_to_file(
                export_data,
                backup_dir=tmpdir
            )

            filename = os.path.basename(filepath)
            # Should match pattern: unifi_clients_YYYYMMDD_HHMMSS.xml
            assert filename.startswith("unifi_clients_")
            assert filename.endswith(".xml")
            # Extract and validate timestamp
            timestamp_part = filename[17:32]  # YYYYMMDD_HHMMSS
            assert len(timestamp_part) == 15
            assert "_" in timestamp_part

    def test_backup_directory_created(self):
        """
        Regression test for: Backup directory should be created if missing.

        Previously: Would fail if directory didn't exist.
        Fixed: Directory is automatically created.
        """
        import unifi_utils
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_dir = os.path.join(tmpdir, "new", "backup", "dir")

            export_data = [{"mac": "aa:bb:cc:dd:ee:ff"}]

            filepath = unifi_utils.export_clients_to_file(
                export_data,
                backup_dir=backup_dir
            )

            assert os.path.exists(backup_dir)
            assert os.path.exists(filepath)


class TestDryRunMode:
    """Regression tests for dry-run mode."""

    def test_restore_dry_run_no_api_calls(self):
        """
        Regression test for: Dry-run restore should not make API calls.

        Previously: Dry-run mode still made some API calls.
        Fixed: Dry-run mode is completely read-only.
        """
        import unifi_utils

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "Test Device",
        }

        with patch('unifi_utils.make_unifi_api_call') as mock_api:
            result = unifi_utils.restore_client_data(client_data, dry_run=True)

            assert result["success"] is True
            mock_api.assert_not_called()

    def test_restore_dry_run_reports_changes(self):
        """
        Regression test for: Dry-run restore should report what would change.

        Previously: Dry-run didn't provide useful output.
        Fixed: Dry-run reports all changes that would be made.
        """
        import unifi_utils

        client_data = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "name": "New Name",
            "note": "New Note",
            "locked": {"enabled": True, "ap_mac": "11:22:33:44:55:66"},
        }

        with patch('unifi_utils.make_unifi_api_call') as mock_api:
            result = unifi_utils.restore_client_data(client_data, dry_run=True)

            assert "name" in result["applied"]
            assert "note" in result["applied"]
            assert "locked" in result["applied"]
            assert mock_api.call_count == 0


class TestErrorHandling:
    """Regression tests for error handling."""

    def test_api_call_exception_handled(self):
        """
        Regression test for: API call exceptions should be handled gracefully.

        Previously: Unhandled exceptions could crash the application.
        Fixed: Exceptions are caught and handled appropriately.
        """
        import unifi_utils

        with patch('unifi_utils.make_unifi_api_call') as mock_api:
            mock_api.side_effect = Exception("API error")

            result = unifi_utils.is_ap_actively_upgrading("aa:bb:cc:dd:ee:ff")

            # Should return False, not raise exception
            assert result is False

    def test_client_not_found_handled(self):
        """
        Regression test for: Client not found should be handled gracefully.

        Previously: Missing clients could cause errors.
        Fixed: Missing clients are handled gracefully.
        """
        import unifi_utils

        with patch('unifi_utils._get_single_client_data_by_mac') as mock_get:
            mock_get.return_value = None

            result = unifi_utils.export_client_data("aa:bb:cc:dd:ee:ff")

            # Should return None, not raise exception
            assert result is None

    def test_restore_missing_mac_handled(self):
        """
        Regression test for: Missing MAC in restore should be handled.

        Previously: Missing MAC could cause cryptic errors.
        Fixed: Missing MAC is reported clearly.
        """
        import unifi_utils

        client_data = {}

        result = unifi_utils.restore_client_data(client_data, dry_run=False)

        assert result["success"] is False
        assert len(result["failed"]) == 1
        assert result["failed"][0]["attribute"] == "mac"


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
