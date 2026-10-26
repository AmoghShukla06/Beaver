#!/usr/bin/env sh
# Real nftables test inside a disposable user + network namespace; never touches the host firewall.
set -eu
cd "$(dirname "$0")/.."
cargo test -p beaver-service --no-run
export BEAVER_HOST_NETNS="$(readlink /proc/self/ns/net)"
exec unshare -Urn -- cargo test -p beaver-service --offline native_nft -- --ignored --nocapture
