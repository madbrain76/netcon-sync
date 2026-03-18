#!/usr/bin/env python3

import unittest
from unittest.mock import patch

import unifi_utils


class TestSsidToggle(unittest.TestCase):
    def test_disable_ssid_single_payload(self):
        """
        Test that disable_ssid sends a single payload.
        Note: Retry logic with minimal payload is not yet implemented.
        """
        ssid = {
            "_id": "ssid-1",
            "name": "IOT",
            "enabled": True,
            "site_id": "default",
            "readonly_field": "value",
        }
        calls = []

        def fake_make_unifi_api_call(method, endpoint, **kwargs):
            calls.append((method, endpoint, kwargs["json"]))
            return {"meta": {"rc": "ok"}}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call", side_effect=fake_make_unifi_api_call):
                result = unifi_utils.disable_ssid("iot")

        self.assertTrue(result)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "PUT")
        self.assertEqual(calls[0][1], f"/api/s/{unifi_utils.UNIFI_SITE_ID}/rest/wlanconf/ssid-1")
        # First (and only) call should include readonly_field (full payload)
        self.assertEqual(calls[0][2]["enabled"], False)
        self.assertEqual(calls[0][2]["readonly_field"], "value")

    def test_enable_ssid_returns_true_when_already_enabled(self):
        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.enable_ssid("IOT")

        self.assertTrue(result)
        mock_api.assert_not_called()

    def test_disable_ssid_returns_false_when_ssid_not_found(self):
        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.disable_ssid("NonExistent")

        self.assertFalse(result)
        mock_api.assert_not_called()

    def test_disable_ssid_returns_true_when_already_disabled(self):
        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": False}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.disable_ssid("iot")

        self.assertTrue(result)
        mock_api.assert_not_called()


class TestApHelpers(unittest.TestCase):
    def test_is_ap_fully_adopted_false_when_not_adopted(self):
        device = {"type": "uap", "adopted": False}
        self.assertFalse(unifi_utils.is_ap_fully_adopted(device))

    def test_is_ap_fully_adopted_true_for_wired_ap_even_with_zero_adopt_status(self):
        device = {
            "type": "uap",
            "adopted": True,
            "adopt_status": 0,
            "uplink": {"type": "wire", "up": True},
        }
        self.assertTrue(unifi_utils.is_ap_fully_adopted(device))


if __name__ == "__main__":
    unittest.main()
