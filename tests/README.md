# netcon-sync Test Framework

This directory contains the test suite for netcon-sync. Tests are organized into:

- **unit/** - Self-contained unit tests with mocks
- **functional/** - Integration and regression tests (some require live controller)

## Running Tests

### Run all unit tests

```bash
./tests/run_tests.py
```

### Run with verbose output

```bash
./tests/run_tests.py --verbose
```

### Run integration tests (requires live controller)

```bash
# Set environment variables
export UNIFI_NETWORK_URL="https://unifi.local"
export UNIFI_USERNAME="admin"
export UNIFI_PASSWORD="password"
export UNIFI_SITE_ID="default"

# Run integration tests
./tests/run_tests.py --live
```

### Run regression tests

```bash
./tests/run_tests.py --regression
```

### Run with pytest directly

```bash
# All unit tests
pytest tests/unit -v

# Specific test file
pytest tests/unit/test_unifi_utils.py -v

# All functional tests
pytest tests/functional -v

# Integration tests only
pytest tests/functional -v -m integration --live-controller

# Regression tests only
pytest tests/functional/test_regression.py -v

# Skip slow tests
pytest tests/ -v -m "not slow"
```

## Test Structure

### Unit Tests (`tests/unit/`)

Self-contained tests that use mocks for all external dependencies.

- `test_unifi_utils.py` - Tests for unifi_utils.py functions
- `test_unifi_climgr.py` - Tests for unifi_climgr.py CLI commands
- `test_ssid_toggle.py` - Tests for SSID toggle functionality

### Functional Tests (`tests/functional/`)

- `test_live_controller.py` - Integration tests requiring live controller
- `test_regression.py` - Regression tests for previously fixed issues
- `test_controller_download.py` - Controller support file download diagnostics
- `test_https_nss.py` - NSS/NSPR HTTPS client tests
- `test_10x_support.py` - UniFi Network 10.x compatibility tests

## Test Markers

Tests can be marked for selective running:

- `@pytest.mark.unit` - Unit tests (fast, no external dependencies)
- `@pytest.mark.integration` - Integration tests (require live controller)
- `@pytest.mark.regression` - Regression tests
- `@pytest.mark.slow` - Slow running tests

## Adding New Tests

### Unit Test Template

```python
import pytest
from unittest.mock import patch, MagicMock

class TestFeature:
    @patch('module.function')
    def test_feature_success(self, mock_function):
        """Test successful feature operation."""
        mock_function.return_value = {"result": "success"}

        # Call the function under test
        result = module.function()

        # Assert the result
        assert result == {"result": "success"}
        mock_function.assert_called_once()
```

### Integration Test Template

```python
import pytest

@pytest.mark.integration
def test_feature_with_live_controller():
    """Test feature with live controller."""
    # Your integration test here
    pass
```

## Test Fixtures

Common fixtures are defined in `conftest.py`:

- `sample_client` - Sample UniFi client data
- `sample_ap` - Sample UniFi AP data
- `sample_ssid` - Sample UniFi SSID data
- `sample_ssids` - List of sample SSIDs
- `sample_clients` - List of sample clients
- `sample_devices` - List of sample devices
- `mock_unifi_response` - Mock HTTP response object
- `mock_api_call_success` - Mock for successful API calls
- `mock_api_call_failure` - Mock for failed API calls
- `temp_env` - Context manager for environment variables

## Environment Variables

For integration tests, set these environment variables:

- `UNIFI_NETWORK_URL` - Controller URL (e.g., `https://unifi.local`)
- `UNIFI_USERNAME` - Controller username
- `UNIFI_PASSWORD` - Controller password
- `UNIFI_SITE_ID` - Site ID (e.g., `default`)

## Debugging Tests

### Enable pytest debugging

```bash
pytest tests/unit -v -s
```

### Run specific test

```bash
pytest tests/unit/test_unifi_utils.py::TestAPHelpers::test_is_ap_fully_adopted -v
```

### Generate test coverage

```bash
pytest tests/ --cov=. --cov-report=html
```

## CI/CD Integration

Tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pytest tests/unit -v
    pytest tests/functional/test_regression.py -v
```
