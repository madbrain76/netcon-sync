"""
Unit tests for unifi_climgr.py CLI commands.

These tests are self-contained and use mocks for all external dependencies.
Run with: pytest tests/unit/test_unifi_climgr.py -v
"""

import pytest
import sys
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestCLIArgumentParsing:
    """Tests for CLI argument parsing via subprocess."""

    def test_help_output_contains_list(self):
        """Test that help output contains list command."""
        result = subprocess.run(
            [sys.executable, "unifi_climgr.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent
        )

        assert result.returncode == 0
        assert "list" in result.stdout

    def test_help_output_contains_backup(self):
        """Test that help output contains backup command."""
        result = subprocess.run(
            [sys.executable, "unifi_climgr.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent
        )

        assert result.returncode == 0
        assert "backup" in result.stdout
        assert "backup --clients" in result.stdout

    def test_help_output_contains_restore(self):
        """Test that help output contains restore command."""
        result = subprocess.run(
            [sys.executable, "unifi_climgr.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.parent
        )

        assert result.returncode == 0
        assert "restore" in result.stdout
        assert "restore --clients" in result.stdout


class TestClientDataFunctions:
    """Tests for client data functions imported from unifi_utils."""

    def test_build_client_row_online(self):
        """Test building client row for online client."""
        from unifi_climgr import _build_client_row

        client = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "is_connected_live": True,
            "is_ap_locked": False,
            "display_ip": "192.168.1.100",
            "live_uptime": 3600,
        }

        result = _build_client_row(client)

        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "test-device"
        assert result["status"] == "Online"
        assert result["ip"] == "192.168.1.100"
        # Uptime format is "1y 1m 1w 1d 1h:00m:01s" style
        assert "1h" in result["uptime"]

    def test_build_client_row_offline(self):
        """Test building client row for offline client."""
        from unifi_climgr import _build_client_row

        client = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "test-device",
            "is_connected_live": False,
            "is_ap_locked": True,
            "display_ip": "",
        }

        result = _build_client_row(client)

        assert result["status"] == "Offline"
        assert result["uptime"] == "N/A"


class TestSSIDFormatting:
    """Tests for SSID formatting functions."""

    def test_build_ssid_row(self):
        """Test building SSID row for display."""
        from unifi_climgr import _build_ssid_row

        ssid = {
            "name": "Guest WiFi",
            "enabled": True,
            "bssid": "11:22:33:44:55:66",
            "ssid": "Guest WiFi",
            "wlangroup_id": "default",
            "is_guest": True,
            "wips_mode": "none",
            "wpa_mode": "WPA2",
            "wlan_bands": ["5g"],
        }

        result = _build_ssid_row(ssid)

        assert result["name"] == "Guest WiFi"
        assert result["enabled"] == "Yes"
        assert "WPA2" in result["security"]
        assert "5GHz" in result["band"]


class TestAPFormatting:
    """Tests for AP formatting functions."""

    @patch('unifi_climgr.unifi_utils.get_ap_state', return_value='connected')
    def test_build_ap_row(self, mock_get_state):
        """Test building AP row for display."""
        from unifi_climgr import _build_ap_row

        ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Living Room AP",
            "type": "uap",
            "model": "U7-Pro",
            "firmware_version": "6.2.28",
            "version": "6.2.28",
            "up": True,
            "connect_ip": "192.168.1.10",
            "ip": "192.168.1.10",
            "state": 0,
            "site_id": "default",
            "uptime": 3600,
            "wired": True,
        }

        result = _build_ap_row(ap, [])

        assert result["name"] == "Living Room AP"
        assert result["mac"] == "11:22:33:44:55:66"
        assert result["ip"] == "192.168.1.10"
        assert result["version"] == "6.2.28"
        assert "1h" in result["uptime"]
        assert result["state"] == "connected"
        assert result["connection"] == "wired"

    @patch('unifi_climgr.unifi_utils.get_ap_state', return_value='disconnected')
    def test_build_ap_row_offline(self, mock_get_state):
        """Test building AP row for offline AP."""
        from unifi_climgr import _build_ap_row

        ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Living Room AP",
            "type": "uap",
            "up": False,
            "uptime": 0,
            "wired": True,
        }

        result = _build_ap_row(ap, [])

        assert result["state"] == "disconnected"
        assert result["uptime"] == "N/A"


class TestUptimeParsing:
    """Tests for uptime parsing functions."""

    def test_parse_uptime_seconds_only(self):
        """Test parsing uptime with seconds only."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("45s")
        assert result == 45

    def test_parse_uptime_minutes_seconds(self):
        """Test parsing uptime with minutes and seconds."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("5m:30s")
        assert result == 330  # 5*60 + 30

    def test_parse_uptime_hours_minutes_seconds(self):
        """Test parsing uptime with hours, minutes, and seconds."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("2h:30m:45s")
        assert result == 9045  # 2*3600 + 30*60 + 45

    def test_parse_uptime_days_hours_minutes_seconds(self):
        """Test parsing uptime with days, hours, minutes, and seconds."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("3d 4h:05m:06s")
        assert result == 273906  # 3*86400 + 4*3600 + 5*60 + 6

    def test_parse_uptime_years_months_weeks_days_hours_minutes_seconds(self):
        """Test parsing uptime with all units."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("1y 2m 3d 4h:05m:06s")
        assert result == 36993906  # 1*365*86400 + 2*30*86400 + 3*86400 + 4*3600 + 5*60 + 6

    def test_parse_uptime_invalid(self):
        """Test parsing invalid uptime."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("invalid")
        assert result == -1

    def test_parse_uptime_na(self):
        """Test parsing N/A uptime."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("N/A")
        assert result == -1

    def test_parse_uptime_empty(self):
        """Test parsing empty uptime."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("")
        assert result == -1

    def test_parse_uptime_none(self):
        """Test parsing None uptime."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds(None)
        assert result == -1

    def test_parse_uptime_weeks(self):
        """Test parsing uptime with weeks."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("1w 2d 3h:4m:5s")
        assert result == 788645  # 1*7*86400 + 2*86400 + 3*3600 + 4*60 + 5

    def test_parse_uptime_years(self):
        """Test parsing uptime with years."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("1y")
        assert result == 31536000  # 1*365*86400

    def test_parse_uptime_months(self):
        """Test parsing uptime with months."""
        from unifi_climgr import _parse_uptime_to_seconds

        result = _parse_uptime_to_seconds("2m")
        assert result == 5184000  # 2*30*86400


class TestStringFormatting:
    """Tests for string formatting functions."""

    def test_strip_default_domain(self):
        """Test stripping default domain from DNS name."""
        from unifi_climgr import _strip_default_domain

        result = _strip_default_domain("device.local", "local")
        assert result == "device"

        result = _strip_default_domain("device.example", "local")
        assert result == "device.example"

        result = _strip_default_domain("device", "local")
        assert result == "device"

    def test_format_uptime_seconds(self):
        """Test formatting uptime in seconds."""
        from unifi_climgr import _format_uptime

        # Test various uptime values - format is "y m w d h:m:s"
        assert _format_uptime(0) == "N/A"
        assert _format_uptime(1) == "1s"
        assert "1m" in _format_uptime(65)  # 1m 5s
        assert "1h" in _format_uptime(3661)  # 1h 1m 1s
        assert "1d" in _format_uptime(90061)  # 1d 1h 1m 1s


class TestSecurityFormatting:
    """Tests for security formatting functions."""

    def test_format_security_display_wpa2(self):
        """Test formatting security display for WPA2."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Secure WiFi",
            "wpa_mode": "WPA2",
            "wpa_passphrase": "password",
        }

        result = _format_security_display(ssid)
        assert "WPA2" in result

    def test_format_security_display_wpa3(self):
        """Test formatting security display for WPA3."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Secure WiFi",
            "wpa_mode": "WPA3",
        }

        result = _format_security_display(ssid)
        assert "WPA3" in result

    def test_format_security_display_open(self):
        """Test formatting security display for open network."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Open WiFi",
            "wpa_mode": "",
        }

        result = _format_security_display(ssid)
        assert len(result) > 0

    def test_format_security_display_security_field(self):
        """Test formatting security display using security field."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Secure WiFi",
            "security": "WPA2",
        }

        result = _format_security_display(ssid)
        assert "WPA2" in result


class TestTopologyFunctions:
    """Tests for AP topology functions."""

    def test_calculate_mesh_hops_root(self):
        """Test calculating mesh hops for root AP."""
        from unifi_climgr import _calculate_mesh_hops

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
        }

        all_devices = [root_ap]

        result = _calculate_mesh_hops(root_ap, all_devices)
        assert result == 0

    def test_calculate_mesh_hops_single_hop(self):
        """Test calculating mesh hops for single hop AP."""
        from unifi_climgr import _calculate_mesh_hops

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
        }
        child_ap = {
            "mac": "11:22:33:44:55:77",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:66",
        }

        all_devices = [root_ap, child_ap]

        result = _calculate_mesh_hops(child_ap, all_devices)
        assert result == 1

    def test_calculate_mesh_hops_double_hop(self):
        """Test calculating mesh hops for double hop AP."""
        from unifi_climgr import _calculate_mesh_hops

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
        }
        child_ap = {
            "mac": "11:22:33:44:55:77",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:66",
        }
        grandchild_ap = {
            "mac": "11:22:33:44:55:88",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:77",
        }

        all_devices = [root_ap, child_ap, grandchild_ap]

        result = _calculate_mesh_hops(grandchild_ap, all_devices)
        assert result == 2

    def test_calculate_mesh_hops_wired(self):
        """Test calculating mesh hops for wired AP (should be 0)."""
        from unifi_climgr import _calculate_mesh_hops

        wired_ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
            "uplink": {"type": "wire"},
        }

        all_devices = [wired_ap]

        result = _calculate_mesh_hops(wired_ap, all_devices)
        assert result == 0

    def test_calculate_mesh_hops_no_uplink(self):
        """Test calculating mesh hops when no uplink info available."""
        from unifi_climgr import _calculate_mesh_hops

        ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
        }

        all_devices = [ap]

        result = _calculate_mesh_hops(ap, all_devices)
        assert result == 0

    def test_calculate_mesh_hops_missing_uplink(self):
        """Test calculating mesh hops when uplink is missing."""
        from unifi_climgr import _calculate_mesh_hops

        ap = {
            "mac": "11:22:33:44:55:66",
            "type": "uap",
            "uplink_ap_mac": None,
        }

        all_devices = [ap]

        result = _calculate_mesh_hops(ap, all_devices)
        assert result == 0

    def test_calculate_mesh_hops_uplink_not_in_devices(self):
        """Test calculating mesh hops when uplink AP is not in devices list."""
        from unifi_climgr import _calculate_mesh_hops

        child_ap = {
            "mac": "11:22:33:44:55:77",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:66",
        }

        all_devices = [child_ap]  # Root AP not in list

        result = _calculate_mesh_hops(child_ap, all_devices)
        assert result == 0  # Falls back to 0 when uplink not found

    def test_calculate_mesh_hops_complex_topology(self):
        """Test calculating mesh hops for complex topology."""
        from unifi_climgr import _calculate_mesh_hops

        root = {"mac": "11:22:33:44:55:66", "type": "uap"}
        child1 = {"mac": "11:22:33:44:55:77", "type": "uap", "uplink_ap_mac": "11:22:33:44:55:66"}
        child2 = {"mac": "11:22:33:44:55:88", "type": "uap", "uplink_ap_mac": "11:22:33:44:55:66"}
        grandchild = {"mac": "11:22:33:44:55:99", "type": "uap", "uplink_ap_mac": "11:22:33:44:55:77"}

        all_devices = [root, child1, child2, grandchild]

        assert _calculate_mesh_hops(root, all_devices) == 0
        assert _calculate_mesh_hops(child1, all_devices) == 1
        assert _calculate_mesh_hops(child2, all_devices) == 1
        assert _calculate_mesh_hops(grandchild, all_devices) == 2


class TestAPSerialization:
    """Tests for AP serialization functions."""

    def test_serialize_ap_topology_empty(self):
        """Test serializing empty AP topology."""
        from unifi_climgr import serialize_ap_topology

        result = serialize_ap_topology([])
        assert result == []

    def test_serialize_ap_topology_single_ap(self):
        """Test serializing single AP topology."""
        from unifi_climgr import serialize_ap_topology

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "uplink_ap_mac": None,
            }
        ]

        result = serialize_ap_topology(aps)
        assert len(result) == 1
        assert result[0]["mac"] == "11:22:33:44:55:66"

    def test_serialize_ap_topology_with_children(self):
        """Test serializing AP topology with children."""
        from unifi_climgr import serialize_ap_topology

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "uplink_ap_mac": None,
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Child AP",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            }
        ]

        result = serialize_ap_topology(aps)
        assert len(result) == 2
        assert result[0]["mac"] == "11:22:33:44:55:66"
        assert result[1]["mac"] == "11:22:33:44:55:77"

    def test_deserialize_ap_topology_empty(self):
        """Test deserializing empty AP topology."""
        from unifi_climgr import deserialize_ap_topology

        result = deserialize_ap_topology([])
        assert result == []

    def test_deserialize_ap_topology_single_ap(self):
        """Test deserializing single AP topology."""
        from unifi_climgr import deserialize_ap_topology

        data = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "uplink_ap_mac": None,
            }
        ]

        result = deserialize_ap_topology(data)
        assert len(result) == 1
        assert result[0]["mac"] == "11:22:33:44:55:66"

    def test_deserialize_ap_topology_with_children(self):
        """Test deserializing AP topology with children."""
        from unifi_climgr import deserialize_ap_topology

        data = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "uplink_ap_mac": None,
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Child AP",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            }
        ]

        result = deserialize_ap_topology(data)
        assert len(result) == 2
        assert result[0]["mac"] == "11:22:33:44:55:66"
        assert result[1]["mac"] == "11:22:33:44:55:77"

    def test_ap_topology_to_json(self):
        """Test converting AP topology to JSON string."""
        from unifi_climgr import ap_topology_to_json

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
            }
        ]

        result = ap_topology_to_json(aps)
        assert isinstance(result, str)
        assert "11:22:33:44:55:66" in result

    def test_ap_topology_from_json(self):
        """Test parsing JSON string to AP topology."""
        from unifi_climgr import ap_topology_from_json
        import json

        data = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "children": [],
            }
        ]

        json_str = json.dumps(data)
        result = ap_topology_from_json(json_str)

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["mac"] == "11:22:33:44:55:66"


class TestAPBranch:
    """Tests for AP branch building function."""

    def test_build_ap_branch_aps_root(self):
        """Test building branch for root AP."""
        from unifi_climgr import _build_ap_branch_aps

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Root AP",
            "type": "uap",
            "wired": True,
        }

        all_devices = [root_ap]

        result = _build_ap_branch_aps(root_ap, all_devices)
        assert len(result) == 1
        assert result[0]["mac"] == "11:22:33:44:55:66"

    def test_build_ap_branch_aps_child(self):
        """Test building branch for child AP."""
        from unifi_climgr import _build_ap_branch_aps

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Root AP",
            "type": "uap",
            "wired": True,
        }
        child_ap = {
            "mac": "11:22:33:44:55:77",
            "name": "Child AP",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:66",
        }

        all_devices = [root_ap, child_ap]

        result = _build_ap_branch_aps(child_ap, all_devices)
        assert len(result) == 2
        assert result[0]["mac"] == "11:22:33:44:55:66"
        assert result[1]["mac"] == "11:22:33:44:55:77"

    def test_build_ap_branch_aps_grandchild(self):
        """Test building branch for grandchild AP."""
        from unifi_climgr import _build_ap_branch_aps

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Root AP",
            "type": "uap",
            "wired": True,
        }
        child_ap = {
            "mac": "11:22:33:44:55:77",
            "name": "Child AP",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:66",
        }
        grandchild_ap = {
            "mac": "11:22:33:44:55:88",
            "name": "Grandchild AP",
            "type": "uap",
            "uplink_ap_mac": "11:22:33:44:55:77",
        }

        all_devices = [root_ap, child_ap, grandchild_ap]

        result = _build_ap_branch_aps(grandchild_ap, all_devices)
        assert len(result) == 3
        assert result[0]["mac"] == "11:22:33:44:55:66"
        assert result[1]["mac"] == "11:22:33:44:55:77"
        assert result[2]["mac"] == "11:22:33:44:55:88"

    def test_build_ap_branch_aps_with_last_uplink(self):
        """Test building branch using last_uplink field."""
        from unifi_climgr import _build_ap_branch_aps

        root_ap = {
            "mac": "11:22:33:44:55:66",
            "name": "Root AP",
            "type": "uap",
            "wired": True,
        }
        child_ap = {
            "mac": "11:22:33:44:55:77",
            "name": "Child AP",
            "type": "uap",
            "last_uplink": {"uplink_mac": "11:22:33:44:55:66"},
        }

        all_devices = [root_ap, child_ap]

        result = _build_ap_branch_aps(child_ap, all_devices)
        assert len(result) == 2


class TestAPMeshDepths:
    """Tests for AP mesh depth calculation."""

    def test_calculate_ap_mesh_depths_empty(self):
        """Test calculating depths for empty AP list."""
        from unifi_climgr import calculate_ap_mesh_depths

        result = calculate_ap_mesh_depths([])
        assert result == {}

    def test_calculate_ap_mesh_depths_single_wired(self):
        """Test calculating depths for single wired AP."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "wired": True,
            }
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {"11:22:33:44:55:66": 0}

    def test_calculate_ap_mesh_depths_single_mesh(self):
        """Test calculating depths for single mesh AP (orphan)."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Orphan AP",
                "type": "uap",
                "uplink_ap_mac": None,
            }
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {"11:22:33:44:55:66": -1}

    def test_calculate_ap_mesh_depths_root_and_child(self):
        """Test calculating depths for root and child AP."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "wired": True,
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Child AP",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            }
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {
            "11:22:33:44:55:66": 0,
            "11:22:33:44:55:77": 1,
        }

    def test_calculate_ap_mesh_depths_complex_topology(self):
        """Test calculating depths for complex mesh topology."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP 1",
                "type": "uap",
                "wired": True,
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Root AP 2",
                "type": "uap",
                "wired": True,
            },
            {
                "mac": "11:22:33:44:55:88",
                "name": "Child AP 1",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            },
            {
                "mac": "11:22:33:44:55:99",
                "name": "Child AP 2",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            },
            {
                "mac": "11:22:33:44:55:aa",
                "name": "Grandchild AP",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:88",
            },
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {
            "11:22:33:44:55:66": 0,
            "11:22:33:44:55:77": 0,
            "11:22:33:44:55:88": 1,
            "11:22:33:44:55:99": 1,
            "11:22:33:44:55:aa": 2,
        }

    def test_calculate_ap_mesh_depths_wired_uplink_type(self):
        """Test calculating depths using wired uplink type."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "uplink": {"type": "wire"},
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Child AP",
                "type": "uap",
                "uplink_ap_mac": "11:22:33:44:55:66",
            }
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {
            "11:22:33:44:55:66": 0,
            "11:22:33:44:55:77": 1,
        }

    def test_calculate_ap_mesh_depths_orphan(self):
        """Test calculating depths with orphan AP."""
        from unifi_climgr import calculate_ap_mesh_depths

        aps = [
            {
                "mac": "11:22:33:44:55:66",
                "name": "Root AP",
                "type": "uap",
                "wired": True,
            },
            {
                "mac": "11:22:33:44:55:77",
                "name": "Orphan AP",
                "type": "uap",
                "uplink_ap_mac": None,
            }
        ]

        result = calculate_ap_mesh_depths(aps)
        assert result == {
            "11:22:33:44:55:66": 0,
            "11:22:33:44:55:77": -1,
        }


class TestSecurityFormatting:
    """Tests for security formatting functions."""

    def test_format_security_display_wpa2(self):
        """Test formatting security display for WPA2."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Secure WiFi",
            "wpa_mode": "WPA2",
            "wpa_passphrase": "password",
        }

        result = _format_security_display(ssid)
        assert "WPA2" in result

    def test_format_security_display_open(self):
        """Test formatting security display for open network."""
        from unifi_climgr import _format_security_display

        ssid = {
            "name": "Open WiFi",
            "wpa_mode": "",
        }

        result = _format_security_display(ssid)
        # Should contain some indication of security status
        assert len(result) > 0


class TestClientRowValidation:
    """Tests for client row validation."""

    def test_build_client_row_missing_fields(self):
        """Test building client row with missing fields."""
        from unifi_climgr import _build_client_row

        # Client with minimal fields
        client = {"mac": "aa:bb:cc:dd:ee:ff"}

        result = _build_client_row(client)

        assert result["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_build_client_row_none_values(self):
        """Test building client row with None values."""
        from unifi_climgr import _build_client_row

        # Client with None values
        client = {
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": None,
            "is_connected_live": None,
        }

        result = _build_client_row(client)

        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["hostname"] == "Unknown Host"


class TestSSIDRowValidation:
    """Tests for SSID row validation."""

    def test_build_ssid_row_missing_fields(self):
        """Test building SSID row with missing fields."""
        from unifi_climgr import _build_ssid_row

        # SSID with minimal fields
        ssid = {"name": "Test SSID"}

        result = _build_ssid_row(ssid)

        assert result["name"] == "Test SSID"


class TestAPRowValidation:
    """Tests for AP row validation."""

    def test_build_ap_row_missing_fields(self):
        """Test building AP row with missing fields."""
        from unifi_climgr import _build_ap_row

        # AP with minimal fields
        ap = {"mac": "11:22:33:44:55:66", "name": "Test AP"}

        result = _build_ap_row(ap, [])

        assert result["name"] == "Test AP"
        assert result["mac"] == "11:22:33:44:55:66"


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
