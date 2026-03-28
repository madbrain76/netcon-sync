"""
Unit tests for pfsense_utils.py.
"""

import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pfsense_utils


class TestPfSenseAPIErrorHandling:
    """Tests for distinguishing HTTP and transport failures."""

    @patch("pfsense_utils._get_opener")
    def test_fetch_dhcp_wraps_tcp_failure_as_transport_error(self, mock_get_opener):
        mock_opener = Mock()
        mock_opener.request.side_effect = urllib.error.URLError(OSError("tcp connect failure"))
        mock_get_opener.return_value = mock_opener

        with pytest.raises(pfsense_utils.PfSenseTransportError) as exc_info:
            pfsense_utils._fetch_dhcp_with_retry("https://pfsense.local/api/v2/services/dhcp_server", {}, {})

        assert "Transport error" in str(exc_info.value)
        assert "tcp connect failure" in str(exc_info.value)
        assert "HTTP 400" not in str(exc_info.value)

    @patch("pfsense_utils._get_opener")
    def test_fetch_dhcp_preserves_http_status(self, mock_get_opener):
        error = urllib.error.HTTPError(
            url="https://pfsense.local/api/v2/services/dhcp_server",
            code=503,
            msg="Service Unavailable",
            hdrs=None,
            fp=None,
        )
        error.read = lambda: b'{"status":"error"}'
        mock_opener = Mock()
        mock_opener.request.side_effect = error
        mock_get_opener.return_value = mock_opener

        with pytest.raises(pfsense_utils.PfSenseHTTPError) as exc_info:
            pfsense_utils._fetch_dhcp_with_retry("https://pfsense.local/api/v2/services/dhcp_server", {}, {})

        assert exc_info.value.status_code == 503

    @patch("pfsense_utils._fetch_dhcp_with_retry")
    @patch("pfsense_utils._ensure_pfsense_config_loaded")
    def test_get_pfsense_dhcp_static_mappings_preserves_transport_error(self, mock_ensure_loaded, mock_fetch):
        pfsense_utils._PFSENSE_URL = "https://pfsense.local"
        pfsense_utils._PFSENSE_APIV2_KEY = "test-key"
        pfsense_utils._PFSENSE_DHCP_INTERFACE = "lan"
        mock_fetch.side_effect = pfsense_utils.PfSenseTransportError("tcp connect failure")

        with pytest.raises(pfsense_utils.PfSenseTransportError) as exc_info:
            pfsense_utils.get_pfsense_dhcp_static_mappings()

        assert "tcp connect failure" in str(exc_info.value)

    @patch("pfsense_utils._fetch_dhcp_with_retry")
    @patch("pfsense_utils._ensure_pfsense_config_loaded")
    def test_get_pfsense_dhcp_static_mappings_returns_staticmaps(self, mock_ensure_loaded, mock_fetch):
        pfsense_utils._PFSENSE_URL = "https://pfsense.local"
        pfsense_utils._PFSENSE_APIV2_KEY = "test-key"
        pfsense_utils._PFSENSE_DHCP_INTERFACE = "lan"
        mock_fetch.return_value = {
            "status": "ok",
            "data": {
                "staticmap": [{"mac": "aa:bb:cc:dd:ee:ff"}]
            },
        }

        result = pfsense_utils.get_pfsense_dhcp_static_mappings()

        assert result == [{"mac": "aa:bb:cc:dd:ee:ff"}]
