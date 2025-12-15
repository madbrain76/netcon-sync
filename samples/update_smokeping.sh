#!/bin/bash

# Run pfsense2smokeping.py to generate the new Targets, then write to the Smokeping config
python ~/projects/netcon-sync/pfsense2smokeping.py | sudo tee /etc/smokeping/config.d/Targets > /dev/null

# Restart Smokeping service with sudo
sudo systemctl restart smokeping

# Print completion message
echo "Smokeping configuration updated and service restarted."


