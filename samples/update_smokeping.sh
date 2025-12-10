#!/bin/bash

# Run fetch.py and process the output with processor.py, then write to the Smokeping config
python ~/projects/netcon-sync/pfsense2smokeping.py | sudo tee /etc/smokeping/config.d/Targets > /dev/null

# Restart Smokeping service with sudo
sudo systemctl restart smokeping

# Print completion message
echo "Smokeping configuration updated and service restarted."


