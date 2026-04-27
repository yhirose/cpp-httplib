#!/usr/bin/env bash
# Reproducer runner for Issue #2431
# (https://github.com/yhirose/cpp-httplib/issues/2431).
#
# Spins up an Ubuntu container, points the resolver at a fake nameserver
# that never replies (so getaddrinfo_a actually hits its timeout), builds
# the test suite with g++ + ASAN, and runs the GetAddrInfoAsyncCancelTest
# cases.
#
# Expected outcomes:
#   - HEAD prior to the fix: ASAN reports a use-after-free / heap-buffer
#     overflow during one of the GetAddrInfoAsyncCancelTest cases.
#   - HEAD with the fix applied: all three cases PASS.
#
# Usage:
#   bash test/run_issue_2431_repro.sh
#
# Requirements: Docker (Linux container support). The container needs
# --privileged because the test binary uses `setarch -R` to disable ASLR
# for ASAN compatibility, and because the script binds UDP/53 inside the
# container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

docker run --rm --privileged \
  -v "$REPO_ROOT:/work" \
  -w /work/test \
  ubuntu:24.04 bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  ca-certificates g++ make pkg-config iptables util-linux coreutils file \
  libssl-dev zlib1g-dev libbrotli-dev libzstd-dev libcurl4-openssl-dev \
  >/dev/null

# Force DNS-only resolution: Ubuntu defaults nsswitch.conf to
# "hosts: files mdns4_minimal [NOTFOUND=return] dns ...", which
# short-circuits to NOTFOUND before reaching glibc DNS code, so the
# gai_cancel() branch never gets exercised.
sed -i "s/^hosts:.*/hosts: dns/" /etc/nsswitch.conf

# Drop all outbound UDP/53 traffic so DNS queries hang silently — this
# matches the iptables-based setup in the original reproducer for
# Issue #2431. Drop incoming responses too, in case anything sneaks
# through (defense in depth).
iptables -I OUTPUT -p udp --dport 53 -j DROP
iptables -I INPUT  -p udp --sport 53 -j DROP
trap "iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null; iptables -D INPUT -p udp --sport 53 -j DROP 2>/dev/null" EXIT

# Sanity check: a real DNS lookup must hang (and time out) now.
if timeout 2 getent hosts example.com >/dev/null 2>&1; then
  echo "ERROR: DNS unexpectedly resolved — DROP / nsswitch is not in effect" >&2
  exit 1
fi
echo "[ok] DNS UDP/53 is being dropped (expected for the repro)"

cd /work/test
echo "=== building test binary (g++ + ASAN) ==="
make CXX=g++ test 2>&1 | tail -5

ARCH=$(uname -m)
echo "=== running GetAddrInfoAsyncCancelTest with CPPHTTPLIB_TEST_ISSUE_2431=1 ==="
set +e
CPPHTTPLIB_TEST_ISSUE_2431=1 setarch "$ARCH" -R \
  ./test --gtest_filter="GetAddrInfoAsyncCancelTest.*" 2>&1
rc=$?
set -e
echo "=== test exit: $rc ==="
exit $rc
'
