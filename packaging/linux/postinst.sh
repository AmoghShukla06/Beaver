#!/bin/sh
# Beaver deb post-install. Packet capture stays opt-in: raw-socket capability is never granted automatically.
echo "Beaver installed. Optional per-app speeds and website names without root:"
echo "  sudo setcap cap_net_raw+ep /usr/bin/beaver-service"
