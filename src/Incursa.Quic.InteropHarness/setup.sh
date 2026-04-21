#!/usr/bin/env bash
set -euo pipefail

echo "Setting up routes..."

# QNS runs packets through the simulator namespace, so endpoint-side checksum
# offload must be disabled or the peer observes invalid UDP checksums.
ethtool -K eth0 tx off

# The Docker-provided per-subnet route bypasses the simulator. Replace it with
# a supernet route that points all QNS traffic at the simulator-side gateway.
ip_v4="$(hostname -I | cut -f1 -d' ')"
gateway_v4="${ip_v4%.*}.2"
unneeded_route_v4="${ip_v4%.*}.0"
echo "Endpoint's IPv4 address is $ip_v4"

route add -net 193.167.0.0 netmask 255.255.0.0 gw "$gateway_v4"
route del -net "$unneeded_route_v4" netmask 255.255.255.0

# The containers are dual-stack; mirror the simulator route setup for IPv6 so
# the harness behaves like the stock QNS endpoint images.
ip_v6="$(hostname -I | cut -f2 -d' ')"
gateway_v6="${ip_v6%:*}:2"
unneeded_route_v6="${ip_v6%:*}:"
echo "Endpoint's IPv6 address is $ip_v6"

ip -d route add fd00:cafe:cafe::/48 via "$gateway_v6"
ip -d route del "$unneeded_route_v6/64"

mkdir -p /logs/qlog
