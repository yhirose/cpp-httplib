#!/usr/bin/env bash
# Reproducer runner for Issue #2431
# (https://github.com/yhirose/cpp-httplib/issues/2431).
#
# Spins up an Ubuntu container, runs the loopback DNS test fixture
# (test/dns_test_fixture.py), routes the container's DNS lookups to
# that fixture via an iptables NAT rule, builds the test suite with
# g++ + ASAN, and runs the GetAddrInfoAsyncCancelTest cases.
#
# Expected outcomes:
#   - HEAD prior to the fix: ASAN reports stack-use-after-return inside
#     getaddrinfo_with_timeout's getaddrinfo_a path during one of the
#     GetAddrInfoAsyncCancelTest cases.
#   - HEAD with the fix applied: all three cases PASS.
#
# Usage:
#   bash test/run_issue_2431_repro.sh
#
# Requirements: Docker (Linux container support). The container needs
# --privileged because the test binary uses `setarch -R` to disable ASLR
# for ASAN compatibility, and because the test job manages iptables
# rules inside the container.

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
  ca-certificates g++ make pkg-config iptables iproute2 util-linux coreutils file \
  python3 \
  libssl-dev zlib1g-dev libbrotli-dev libzstd-dev libcurl4-openssl-dev \
  >/dev/null

# Force DNS-only resolution: Ubuntu defaults nsswitch.conf to
# "hosts: files mdns4_minimal [NOTFOUND=return] dns ...", which
# short-circuits to NOTFOUND before reaching glibc DNS code, so the
# gai_cancel() branch never gets exercised.
sed -i "s/^hosts:.*/hosts: dns/" /etc/nsswitch.conf

# Start the loopback DNS test fixture (delayed UDP responder).
DNS_FIXTURE_PORT=15353
DNS_FIXTURE_DELAY=3
python3 /work/test/dns_test_fixture.py "$DNS_FIXTURE_PORT" "$DNS_FIXTURE_DELAY" \
  >/tmp/dns_fixture.log 2>&1 &
FIXTURE_PID=$!

# Route the container DNS lookups to the fixture; conntrack handles the
# reply path automatically. /etc/resolv.conf is left untouched.
iptables -t nat -I OUTPUT -p udp --dport 53 \
  -j REDIRECT --to-port "$DNS_FIXTURE_PORT"

trap '"'"'iptables -t nat -F OUTPUT 2>/dev/null || true; kill "$FIXTURE_PID" 2>/dev/null || true'"'"' EXIT

# Wait for the fixture to start listening.
for _ in $(seq 1 50); do
  if ss -lun "( sport = :$DNS_FIXTURE_PORT )" | grep -q ":$DNS_FIXTURE_PORT"; then
    break
  fi
  sleep 0.1
done
ss -lun "( sport = :$DNS_FIXTURE_PORT )" | grep -q ":$DNS_FIXTURE_PORT" || {
  echo "ERROR: dns_test_fixture failed to start" >&2
  cat /tmp/dns_fixture.log >&2 || true
  exit 1
}

# Sanity check: a DNS lookup must take at least the fixture delay
# (proving the NAT rule routes the query to the fixture).
start=$(date +%s)
getent hosts unresolvable-host.invalid >/dev/null 2>&1 || true
elapsed=$(( $(date +%s) - start ))
if [ "$elapsed" -lt 2 ]; then
  echo "ERROR: lookup returned in ${elapsed}s; fixture not in DNS path" >&2
  exit 1
fi
echo "[ok] DNS lookups are routed to the test fixture (took ${elapsed}s)"

cd /work/test
echo "=== building test binary (g++ + ASAN) ==="
make CXX=g++ test 2>&1 | tail -5

ARCH=$(uname -m)
echo "=== running GetAddrInfoAsyncCancelTest with CPPHTTPLIB_TEST_ISSUE_2431=1 ==="
set +e
CPPHTTPLIB_TEST_ISSUE_2431=1 \
ASAN_OPTIONS=detect_stack_use_after_return=1 \
setarch "$ARCH" -R \
  ./test --gtest_filter="GetAddrInfoAsyncCancelTest.*" 2>&1
rc=$?
set -e
echo "=== test exit: $rc ==="
exit $rc
'
