import sys
import json
import re
import io
import subprocess
from collections import namedtuple

# Define device categories with namedtuple
DeviceCategory = namedtuple("DeviceCategory", ["name", "suffix", "description"])

device_categories = [
    DeviceCategory("wired", "- wired", "Wired devices"),
    DeviceCategory("wifi", "- wifi", "WiFi devices"),
    DeviceCategory("bridged", "- bridged", "Bridged devices"),
    DeviceCategory("other", "", "Other devices"), # 'other' has no suffix as it's a fallback
]

# Function to create sections and add sorted DHCP mappings
def create_smokeping_section(f_stream, section_name, title, mappings):
    """
    Create a section for SmokePing with DHCP mappings.
    f_stream: The file-like object to write to (e.g., sys.stdout).
    """
    if not mappings:
        return  # Skip writing the section if there are no mappings

    # Find the correct DeviceCategory by name
    category = next((cat for cat in device_categories if cat.name == section_name), None)

    if not category:
        raise ValueError(f"No device category found for name: {section_name}")

    # Properly formatted section header with correct case and title
    f_stream.write(
        f"+ {category.name.capitalize()}\n"  # Capitalize only the first letter
        f"menu = {title}\n"  # User-friendly menu without suffix
        f"title = {title}\n\n"
    )

    # Add subsections for each mapping
    for mapping in mappings:
        hostname = mapping.get("hostname", "Unknown")
        ip_address = mapping.get("ipaddr", "0.0.0.0")
        # Ensure description handles potential None, and replaces '#'
        description = mapping.get("descr")
        if description is None:
            description = hostname
        description = description.replace("#", "number ")

        mac_address = mapping.get("mac", "")  # Get the MAC address

        # If description is empty, use hostname for the menu
        menu = description if description else hostname

        # Sanitize hostname for subsection name (replace spaces with underscores)
        subsection_name = f"{hostname.replace(' ', '_')}"
        
        f_stream.write(
            f"++ {subsection_name}\n"
            f"menu = {menu}\n"  # Use sanitized description/hostname for menu
            f"title = {hostname} ({ip_address})\n"
            f"host = {ip_address}\n"
            f"# MAC Address: {mac_address}\n\n"
        )

def generate_smokeping_config(dhcp_static_mappings_list: list) -> str:
    """
    Generates a SmokePing configuration string based on a list of DHCP static mappings.

    Args:
        dhcp_static_mappings_list (list): A list of dictionaries, where each dictionary
                                          represents a DHCP static mapping (e.g., as
                                          returned by get_pfsense_dhcp_static_mappings).

    Returns:
        str: The generated SmokePing configuration.
    """
    output_buffer = io.StringIO()  # Use StringIO to capture output

    # Extract DHCP static mappings and create a dictionary with keys as descriptions
    # The input `dhcp_static_mappings_list` is already the list we need to iterate over.
    mappings = {}
    for mapping in dhcp_static_mappings_list:
        # Get description, fallback to hostname if empty or missing, then strip spaces
        description = mapping.get("descr", "").strip()
        if not description:  # if the description is empty, use the hostname
            description = mapping.get("hostname", "").strip()
        mappings[description] = mapping # Use the processed description as key

    # Initialize empty lists for different device categories
    categorized_mappings = {category.name: [] for category in device_categories}

    # Process mappings and categorize them
    for desc, mapping in mappings.items():
        matched = False
        desc_stripped = desc.strip()  # Remove leading and trailing whitespace

        # Check against all categories, adding to "other" if no match
        for category in device_categories:
            # We match only if the description ends with the category's suffix (case insensitive)
            if category.suffix and desc_stripped.lower().endswith(category.suffix.lower()):
                categorized_mappings[category.name].append(mapping)
                matched = True
                break

        if not matched:
            # If no match found, categorize under "other"
            categorized_mappings["other"].append(mapping)

    # Sort the categorized lists based on hostname
    for category in device_categories:
        categorized_mappings[category.name].sort(key=lambda m: m.get("hostname", ""))

    # Write configuration header directly to the buffer
    output_buffer.write(
        "*** Targets ***\n\n"
        "probe = FPing\n"
        "menu = Top\n"
        "title = Network Latency Monitoring\n"
        "remark = SmokePing configuration for monitoring DHCP static mappings, WiFi devices, Internet connections, bridged devices, and other devices.\n\n"
    )

    # Create sections for each category, skipping "other" if it's empty
    for category in device_categories:
        if category.name == "other" and not categorized_mappings["other"]:
            continue
        create_smokeping_section(output_buffer, category.name, category.description, categorized_mappings[category.name])

    # Top-level section for Internet connections
    output_buffer.write(
        "+ Internet\n"
        "menu = Internet\n"
        "title = Internet Connections\n\n"
        "++ GoogleDNS\nmenu = Google DNS\ntitle = Google DNS\nhost = 8.8.8.8\n# MAC Address: Not applicable\n\n"
    )
    
    return output_buffer.getvalue()


if __name__ == "__main__":
    """
    Main entry point for SmokePing configuration generation.
    
    Fetches DHCP static mappings from pfSense using pfsense_utils API and
    generates SmokePing configuration for network monitoring.
    """
    # Initialize NSS database before any HTTPS connections
    import nss.nss as nss_core
    from pathlib import Path
    import subprocess
    
    nss_db_dir = Path.home() / ".netcon-sync"
    nss_db_dir.mkdir(parents=True, exist_ok=True)
    
    # Create NSS database if it doesn't exist
    cert_db = nss_db_dir / "cert9.db"
    if not cert_db.exists():
        try:
            subprocess.run(
                ["certutil", "-N", "-d", str(nss_db_dir), "-f", "/dev/null"],
                check=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print(f"Error creating NSS database: {e.stderr.decode() if e.stderr else e}", file=sys.stderr)
            sys.exit(1)
    
    # Initialize NSS
    try:
        nss_core.nss_init(str(nss_db_dir))
    except Exception as e:
        print(f"Error initializing NSS: {e}", file=sys.stderr)
        sys.exit(1)
    
    try:
        from pfsense_utils import get_pfsense_dhcp_static_mappings
        
        # Fetch DHCP mappings from pfSense (uses 'lan' by default from config)
        dhcp_mappings = get_pfsense_dhcp_static_mappings()
    except ImportError:
        print("Error: pfsense_utils.py not found. Ensure it's in the Python path.", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: pfSense configuration missing: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to fetch DHCP mappings from pfSense: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate the SmokePing config
    smokeping_config = generate_smokeping_config(dhcp_mappings)

    # Print the generated config to standard output
    print(smokeping_config)
