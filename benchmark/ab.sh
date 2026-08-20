#!/usr/bin/env bash
#
# A/B throughput comparison between two git refs.
#
# Usage: ./ab.sh [--base REF] [--head REF] [--rounds N] [--duration S]
#                [--connections N] [--threads N] [--path PATH] [--tls]
#                [--large-mib N] [--timeout S]
#
# --path selects the workload. The harness serves:
#   /                  small body via set_content(); the response line, the
#                      headers and the body already share a single write(), so
#                      this is the least sensitive case
#   /large             large body via set_content()
#   /static/small.js   1 KiB file from a mount point, where the headers and the
#                      body are two separate writes
#   /static/large.bin  same, with the body large enough to dominate
#
# --large-mib sizes the two large workloads (default 1).
#
# --tls runs the same workload over HTTPS, which writes through
# SSLSocketStream instead of SocketStream.
#
# --timeout is bombardier's per-request timeout. Its 2s default aborts large
# TLS responses, and the run then fails on the non-2xx check.
#
# Absolute numbers from a single run are meaningless: on a quiet 8-core laptop
# the same binary varies by +/-20% run to run, and shared CI runners are worse.
# So both refs are built and then measured alternately in the same session, and
# only the ratio of the medians is reported.
#
# Requires: bombardier, python3, g++ (or $CXX), git.

set -euo pipefail

BASE_REF="master"
HEAD_REF="HEAD"
ROUNDS=5
DURATION="5s"
CONNECTIONS=10
THREADS=""
PORT=8080
REQ_PATH="/"
TLS=0
LARGE_MIB=1
TIMEOUT="30s"

while [ $# -gt 0 ]; do
  case "$1" in
    --base) BASE_REF="$2"; shift 2 ;;
    --head) HEAD_REF="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --connections) CONNECTIONS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --path) REQ_PATH="$2"; shift 2 ;;
    --large-mib) LARGE_MIB="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --tls) TLS=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

command -v bombardier >/dev/null || { echo "Error: bombardier not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Error: python3 not found" >&2; exit 1; }

REPO_ROOT=$(git rev-parse --show-toplevel)
CXX=${CXX:-g++}

# Default the thread pool to the core count. The committed benchmark Makefile
# hardcodes 16, which heavily oversubscribes a 2-4 vCPU CI runner and inflates
# the variance we are trying to see through.
if [ -z "$THREADS" ]; then
  THREADS=$(python3 -c 'import os; print(os.cpu_count() or 4)')
fi

WORKDIR=$(mktemp -d)
cleanup() {
  pkill -f "$WORKDIR/.*/server-ab" 2>/dev/null || true
  git -C "$REPO_ROOT" worktree remove --force "$WORKDIR/base" 2>/dev/null || true
  git -C "$REPO_ROOT" worktree remove --force "$WORKDIR/head" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

BASE_SHA=$(git -C "$REPO_ROOT" rev-parse --short "$BASE_REF")
HEAD_SHA=$(git -C "$REPO_ROOT" rev-parse --short "$HEAD_REF")

echo "==> base: $BASE_REF ($BASE_SHA)"
echo "==> head: $HEAD_REF ($HEAD_SHA)"
echo "==> rounds=$ROUNDS duration=$DURATION connections=$CONNECTIONS threads=$THREADS"
echo "==> path=$REQ_PATH tls=$TLS large=${LARGE_MIB}MiB"
echo ""

if [ "$BASE_SHA" = "$HEAD_SHA" ]; then
  echo "Note: base and head are the same commit; this measures harness noise."
  echo ""
fi

# --- Toolchain bits that depend on --tls ---
SCHEME="http"
INSECURE=""
TLS_CXXFLAGS=""
TLS_LDFLAGS=""
TLS_ARGS=""
if [ "$TLS" = "1" ]; then
  SCHEME="https"
  INSECURE="-k"
  TLS_CXXFLAGS="-DCPPHTTPLIB_OPENSSL_SUPPORT"
  TLS_LDFLAGS="-lssl -lcrypto"
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl; then
    TLS_CXXFLAGS="$TLS_CXXFLAGS $(pkg-config --cflags openssl)"
    TLS_LDFLAGS="$(pkg-config --libs openssl)"
  elif command -v brew >/dev/null 2>&1 && brew --prefix openssl >/dev/null 2>&1; then
    OPENSSL_PREFIX=$(brew --prefix openssl)
    TLS_CXXFLAGS="$TLS_CXXFLAGS -I$OPENSSL_PREFIX/include"
    TLS_LDFLAGS="-L$OPENSSL_PREFIX/lib -lssl -lcrypto"
  fi
  if [ "$(uname -s)" = "Darwin" ]; then
    TLS_LDFLAGS="$TLS_LDFLAGS -framework CoreFoundation -framework Security"
  fi
  TLS_ARGS="--cert $REPO_ROOT/test/cert.pem --key $REPO_ROOT/test/key.pem"
  for f in "$REPO_ROOT/test/cert.pem" "$REPO_ROOT/test/key.pem"; do
    [ -f "$f" ] || { echo "Error: $f not found" >&2; exit 1; }
  done
fi

# --- Build both refs ---
# The harness source always comes from the invoking worktree, so both refs run
# an identical workload and a ref that predates a harness change stays
# measurable. Only httplib.h varies, through -I.
HARNESS="$REPO_ROOT/benchmark/cpp-httplib/main.cpp"
[ -f "$HARNESS" ] || { echo "Error: $HARNESS not found" >&2; exit 1; }

build() {
  local name=$1 ref=$2
  git -C "$REPO_ROOT" worktree add --detach --quiet "$WORKDIR/$name" "$ref"
  "$CXX" -o "$WORKDIR/$name/server-ab" -O2 -std=c++11 \
    -I"$WORKDIR/$name" \
    -DCPPHTTPLIB_THREAD_POOL_COUNT="$THREADS" \
    $TLS_CXXFLAGS \
    "$HARNESS" -lpthread $TLS_LDFLAGS
}

echo "==> Building..."
build base "$BASE_REF"
build head "$HEAD_REF"

# --- Measure one ref once, echo rps ---
measure() {
  local name=$1
  local json rc

  "$WORKDIR/$name/server-ab" --port "$PORT" --dir "$WORKDIR/$name-www" \
    --large-mib "$LARGE_MIB" $TLS_ARGS >/dev/null 2>&1 &
  local pid=$!

  # Wait for the listener (no dependency on nc)
  local i
  for i in $(seq 1 200); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then exec 3>&- 3<&-; break; fi
    sleep 0.05
  done

  set +e
  json=$(bombardier -c "$CONNECTIONS" -d "$DURATION" -t "$TIMEOUT" -o json -p r $INSECURE \
    "$SCHEME://127.0.0.1:$PORT$REQ_PATH" 2>/dev/null)
  rc=$?
  set -e

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  # Wait for the port to be released before the next run
  for i in $(seq 1 200); do
    if ! (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then break; fi
    exec 3>&- 3<&-
    sleep 0.05
  done

  if [ $rc -ne 0 ] || [ -z "$json" ]; then
    echo "Error: bombardier failed for $name" >&2
    exit 1
  fi

  python3 -c '
import json, sys
r = json.load(sys.stdin)["result"]
total = sum(r[k] for k in ("req1xx","req2xx","req3xx","req4xx","req5xx","others"))
bad = total - r["req2xx"]
if bad:
    sys.stderr.write("Error: %d non-2xx/error responses\n" % bad)
    sys.exit(1)
print("%.1f" % (total / r["timeTakenSeconds"]))
' <<<"$json"
}

# --- Alternate, flipping the order each round to cancel ordering bias ---
BASE_RESULTS=()
HEAD_RESULTS=()

echo ""
echo "==> Measuring..."
for ((r = 1; r <= ROUNDS; r++)); do
  if (( r % 2 == 1 )); then order=("base" "head"); else order=("head" "base"); fi
  line="    round $r:"
  for name in "${order[@]}"; do
    rps=$(measure "$name")
    if [ "$name" = "base" ]; then BASE_RESULTS+=("$rps"); else HEAD_RESULTS+=("$rps"); fi
    line="$line  $name=$rps"
  done
  echo "$line"
done

# --- Report ---
SUMMARY=$(python3 -c '
import statistics, sys
from itertools import combinations

base = [float(x) for x in sys.argv[1].split()]
head = [float(x) for x in sys.argv[2].split()]
bm, hm = statistics.median(base), statistics.median(head)

def spread(v):
    return (max(v) - min(v)) / statistics.median(v) * 100

def u_stat(a, b):
    """Mann-Whitney U: number of (a, b) pairs where a > b, ties count a half."""
    return sum((x > y) + 0.5 * (x == y) for x in a for y in b)

def exact_p(a, b):
    """Two-sided permutation p-value. A single slow round cannot swing this
    the way a min/max spread check can."""
    n1, n2 = len(a), len(b)
    pooled = a + b
    observed = abs(u_stat(a, b) - n1 * n2 / 2)
    total = extreme = 0
    for idx in combinations(range(n1 + n2), n1):
        s = set(idx)
        ga = [pooled[i] for i in idx]
        gb = [pooled[i] for i in range(n1 + n2) if i not in s]
        total += 1
        if abs(u_stat(ga, gb) - n1 * n2 / 2) >= observed:
            extreme += 1
    return extreme / total

print("| | median req/s | min | max | spread |")
print("|---|---|---|---|---|")
print("| base | %.0f | %.0f | %.0f | %.1f%% |" % (bm, min(base), max(base), spread(base)))
print("| head | %.0f | %.0f | %.0f | %.1f%% |" % (hm, min(head), max(head), spread(head)))
print("")
print("**ratio: %.3fx** (%+.1f%%)" % (hm / bm, (hm / bm - 1) * 100))
print("")

if len(base) + len(head) > 20:
    print("> %d rounds: skipping the permutation test (too many combinations)."
          % len(base))
else:
    p = exact_p(base, head)
    if p <= 0.05:
        print("> Separation is consistent across rounds (permutation p = %.3f)." % p)
    else:
        print("> Not separated from noise (permutation p = %.3f). Inconclusive;" % p)
        print("> raise --rounds or --duration, or run on a quieter machine.")
    min_p = exact_p(list(range(len(base))),
                    list(range(len(base), len(base) + len(head))))
    if min_p > 0.05:
        print(">")
        print("> With %d rounds even perfect separation only reaches p = %.3f,"
              % (len(base), min_p))
        print("> so this test can never call a win. Use --rounds 4 or more.")
' "${BASE_RESULTS[*]}" "${HEAD_RESULTS[*]}")

echo ""
echo "$SUMMARY"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Benchmark A/B"
    echo ""
    echo "- base: \`$BASE_REF\` ($BASE_SHA)"
    echo "- head: \`$HEAD_REF\` ($HEAD_SHA)"
    echo "- rounds=$ROUNDS duration=$DURATION connections=$CONNECTIONS threads=$THREADS"
    echo ""
    echo "$SUMMARY"
  } >> "$GITHUB_STEP_SUMMARY"
fi
