#!/bin/bash
unifi_climgr.py reconnect_client --filter_online --filter_signal_below=-75 +mac +dns_name +signal
