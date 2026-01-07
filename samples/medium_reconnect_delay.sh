#!/bin/bash
unifi_climgr.py reconnect_client --filter_unlocked --filter_online --filter_signal_below=-65 --delay=2500 +description +signal
