#!/usr/bin/env sh
set -eu
export BEAVER_HOST_NETNS="$(readlink /proc/self/ns/net)"
exec unshare -Urn -- python3 "$(dirname "$0")/test-linux-firewall.py"
