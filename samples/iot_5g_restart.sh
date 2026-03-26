#!/bin/bash
unifi_climgr.py disable --ssids "Stupider"
sleep 60
unifi_climgr.py enable --ssids "Stupider"

