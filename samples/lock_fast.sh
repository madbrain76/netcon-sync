#!/bin/bash
unifi_climgr.py lock_client --filter_online --filter_locked --filter_signal_above=-70 --connected_ap
