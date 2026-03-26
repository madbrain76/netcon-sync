#!/bin/bash
unifi_climgr.py disable --ssids "Not so smart !"
sleep 60
unifi_climgr.py enable --ssids "Not so smart !"

