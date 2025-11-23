# netcon-sync - Network Configuration Synchronization tool
Author : Julien Pierre, with the help of Code Rhapsody

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A comprehensive Python utility suite for synchronizing network configuration.
Currently supports pfSense router, and UniFi controllers. Includes DHCP reservation sync, certificate management, and network client administration.

## Background

I maintain a very large smart home network, with hundreds of IOT devices. I use pfSense as a router rather than a Unifi gateway, and Ubiquiti Unifi access points, as many others do.
The main reason I use pfSense is that my router is in my home office, and I need a 100% silent fanless 10 Gbase-t router. Ubiquiti does not produce one. Thus, I built my own fanless PC,
with an AMD 5700G APU, X470 motherboard, NH-D15 CPU cooler, and X550-T2 dual 10 Gbase-t NIC. It has been my router for the last few years, and is completely silent.

Given this split between pfSense and Unifi, I selected the "source of truth" for my clients as the DHCP reservation table in pfSense, specifically the MAC, IPv4 reservation, hostname, and description.

## Features

- 🔄 **DHCP Sync** - Exports DHCP static mappings from pfSense to UniFi as known clients
- 🔐 **NSS/NSPR TLS** - Enterprise-grade certificate handling with NSS database
- 📋 **Flexible Filtering** - Configurable client description suffix matching
- ✅ **Batch Verification** - Confirm clients were created in UniFi
- 🗑️ **Orphan Management** - Detect and optionally delete Unifi clients that are not present in pfSense
- 🔄 **Automatic Retry** - Exponential backoff for transient failures
- ✔️ **MAC Validation** - Strict format validation (colon delimiters)
- 📊 **Detailed Reporting** - Clear breakdown of success/failed/filtered clients

## Prerequisites

- a pfSense or pfSense+ router
- matching pfSense APIv2 package installed. Available at https://github.com/jaredhendrickson13/pfsense-api
- APIv2 key configured in pfSense API
- Python 3.7+
- `requests` library
- NSS/NSPR libraries (for secure TLS)
- NSS tools (for certificate management)

## Installation

### Quick setup

1. Clone the repository:
```bash
git clone https://github.com/madbrain76/netcon-sync.git
cd netcon-sync
```

2. Run the installer to create an isolated virtual environment:
```bash
./install_deps.sh
```

This creates a Python venv at `~/.venv-netcon-sync` with all dependencies.

3. Configure environment variables. See Configuration below.

4. Trust your CA or server certificate(s). See Certificate Management below.

## Configuration

### Required Environment Variables

```bash
# UniFi Controller
export UNIFI_NETWORK_URL="https://192.168.1.100:8443"
export UNIFI_USERNAME="email@domain.com"
export UNIFI_PASSWORD="your_password"

# pfSense (for sync operations)
export PFSENSE_URL="https://192.168.1.1"
export PFSENSE_APIV2_KEY="your_api_key"
```

### Optional Environment Variables

```bash
export UNIFI_SITE_ID="default"              # UniFi site ID (default: "default")
export PFSENSE_DHCP_INTERFACE="lan"         # pfSense interface (default: "lan")
```

## Certificate Management

Trust a CA certificate:
```bash
./pfsense2unifi.py trust --ca /path/to/ca_cert.pem
```

Trust a server certificate:
```bash
./pfsense2unifi.py trust --server $UNIFI_NETWORK_URL
./unifi_climgr.py trust --server $PFSENSE_URL
```

## Project Structure

```
.
├── pfsense2unifi.py           # Sync DHCP mappings from pfSense to UniFi
├── unifi_climgr.py            # UniFi client and AP management CLI
├── pfsense_utils.py           # pfSense API utilities
├── unifi_utils.py             # UniFi API utilities
├── unifi_network_manager.py    # Comprehensive network management CLI
├── config.py                  # Configuration management
├── trust.py                   # Certificate handling
├── http_tls_nss.py            # NSS/NSPR HTTP client
├── install_deps.sh            # Dependency installer
├── requirements.txt           # Python dependencies
├── README.md                  # This file (overview)
├── pfsense2unifi.md           # pfsense2unifi.py documentation
├── unifi_climgr.md            # unifi_climgr.py documentation
└── LICENSE                    # GPL-3.0 license
```

## Disclaimer & Backup Warning

⚠️ **IMPORTANT - BACKUP BEFORE USE**

This tool directly modifies network configurations. Always:

- **BACKUP YOUR UNIFI CONFIGURATION BEFORE ANY MIGRATION** - Use UniFi's built-in backup feature or export your configuration
- Test in a non-production environment first
- Maintain backups of your configurations
- Review changes before running in production

Additional disclaimers:

- This tool was almost entirely vibe-coded with waywardgeek's Code Rhapsody, with minimal supervision and human review.
While I have been writing low-level C, C++ and assembly code, mainly in the field of enterprise security, for over 30 years. I can barely read Python, let alone write it. I'm comfortable using this tool in production in my own home. Please think thrice about using this tool in a business production environment. If you take that chance, I'd like to hear about it.
- Only U6-LR and NanoHD Unifi APs have been tested. Other Unifi APs, switches and gateways have not been tested, because I don't currently own any.
- Tested only with pfSense+ 25.07.1, pfSense APIv2, and Unifi Network 9.5.21 GA
- Not tested with Unifi OS

## Future plans
- Integrate pfsense2smokeping

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

For issues or feature requests, please open a GitHub issue, preferably with a pull request.

---

**Made with ❤️ for network administrators**
