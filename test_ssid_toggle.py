#!/usr/bin/env python3

import unittest
from unittest.mock import patch

import unifi_utils


class TestSsidToggle(unittest.TestCase):
    def test_disable_ssid_retries_with_minimal_payload(self):
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
            if len(calls) == 1:
                raise Exception("HTTP 400: full payload rejected")
            return {"meta": {"rc": "ok"}}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call", side_effect=fake_make_unifi_api_call):
                result = unifi_utils.disable_ssid("iot")

        self.assertTrue(result)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "PUT")
        self.assertEqual(calls[0][1], f"/api/s/{unifi_utils.UNIFI_SITE_ID}/rest/wlanconf/ssid-1")
        self.assertEqual(calls[0][2]["enabled"], False)
        self.assertEqual(calls[0][2]["readonly_field"], "value")
        self.assertEqual(calls[1][2], {"enabled": False, "name": "IOT"})

    def test_enable_ssid_returns_true_when_already_enabled(self):
        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call") as mock_api:
                result = unifi_utils.enable_ssid("IOT")

        self.assertTrue(result)
        mock_api.assert_not_called()

    def test_disable_ssid_returns_false_after_both_payloads_fail(self):
        ssid = {"_id": "ssid-1", "name": "IOT", "enabled": True}

        with patch.object(unifi_utils, "get_ssids", return_value=[ssid]):
            with patch.object(unifi_utils, "make_unifi_api_call", side_effect=Exception("HTTP 400")) as mock_api:
                result = unifi_utils.disable_ssid("IOT")

        self.assertFalse(result)
        self.assertEqual(mock_api.call_count, 2)


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
