#!/bin/bash
unifi_climgr.py lock_client --filter_online --filter_unlocked --filter_signal_above=-50 --connected_ap --filter_by_ssid=IOT
