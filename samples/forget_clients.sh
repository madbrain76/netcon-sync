#!/bin/bash
unifi_climgr.py disable --ssids IOT
unifi_climgr.py forget --clients
pfsense2unifi.py sync --delete-orphans
sleep 30
unifi_climgr.py enable --ssids IOT

