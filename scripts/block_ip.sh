#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: block_ip.sh <IP>"
  exit 1
fi

IP="$1"

# Simple safety: do NOT block gateway or Pi itself or your laptop
# TODO: UPDATE THESE IPs to match your CURRENT network before enabling blocking.
if [ "$IP" = "192.168.46.1" ] || [ "$IP" = "192.168.46.252" ] || [ "$IP" = "192.168.46.12" ]; then
  echo "Refusing to block critical IP: $IP"
  exit 0
fi

echo "Blocking IP: $IP"
sudo iptables -I INPUT -s "$IP" -j DROP
