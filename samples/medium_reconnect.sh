#!/bin/bash
# I use this in a cron job on my Raspberry Pi
# */3 * * * * . /home/madbrain/.bashrc && /home/madbrain/scripts/netcon-sync/samples/slow_reconnect.sh >> /home/madbrain/reconnect.log 2>&1

unifi_climgr.py reconnect_client --filter_online --filter_signal_below=-70 +description +signal
