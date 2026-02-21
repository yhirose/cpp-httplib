#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 || -z "${1// }" ]]; then
  echo "Usage: $0 <comma-separated-full-test-file-paths>"
  echo "Example: $0 /workspace/test/test_thread_pool.cc,/workspace/test/test_websocket_heartbeat.cc"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

install_deps_apt() {
  local sudo_cmd=""
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo_cmd="sudo"
    else
      echo "Error: need root or sudo for apt-get installs."
      exit 1
    fi
  fi

  export DEBIAN_FRONTEND=noninteractive
  ${sudo_cmd} apt-get update
  ${sudo_cmd} apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    file \
    libbrotli-dev \
    libcurl4-openssl-dev \
    libmbedtls-dev \
    libssl-dev \
    libzstd-dev \
    ninja-build \
    openssl \
    pkg-config \
    python3 \
    zlib1g-dev
}

install_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    install_deps_apt
    return
  fi

  echo "Error: unsupported package manager. This script currently supports apt-based systems."
  exit 1
}

run_test_target() {
  local raw_path="$1"
  raw_path="${raw_path//$'\r'/}"
  raw_path="${raw_path//\\//}"
  raw_path="$(trim "$raw_path")"

  if [[ -z "${raw_path}" ]]; then
    return
  fi

  local test_file
  test_file="$(basename "$raw_path")"

  case "${test_file}" in
    test.cc)
      make -C test test CXX="${CXX:-g++}"
      if [[ -n "${GTEST_FILTER_TEST_CC:-}" ]]; then
        (cd test && ./test --gtest_color=yes --gtest_filter="${GTEST_FILTER_TEST_CC}")
      else
        # Online tests are environment-dependent; skip by default for reproducibility.
        (cd test && ./test --gtest_color=yes --gtest_filter="-*.*_Online")
      fi
      ;;
    test_thread_pool.cc)
      make -C test test_thread_pool CXX="${CXX:-g++}"
      (cd test && ./test_thread_pool --gtest_color=yes)
      ;;
    test_websocket_heartbeat.cc)
      make -C test test_websocket_heartbeat CXX="${CXX:-g++}"
      (cd test && ./test_websocket_heartbeat --gtest_color=yes)
      ;;
    test_proxy.cc)
      if ! command -v docker >/dev/null 2>&1; then
        echo "Error: test_proxy.cc requires docker, but docker is not installed."
        exit 1
      fi
      make -C test proxy CXX="${CXX:-g++}"
      ;;
    cmake_mbedtls_component_test.sh)
      (cd test && bash ./cmake_mbedtls_component_test.sh)
      ;;
    *)
      echo "Error: unsupported test file path '${raw_path}'."
      echo "Supported files: test/test.cc, test/test_thread_pool.cc, test/test_websocket_heartbeat.cc, test/test_proxy.cc, test/cmake_mbedtls_component_test.sh"
      exit 1
      ;;
  esac
}

install_dependencies

IFS=',' read -r -a test_paths <<< "$1"
if [[ ${#test_paths[@]} -eq 0 ]]; then
  echo "Error: no test paths found."
  exit 1
fi

for test_path in "${test_paths[@]}"; do
  run_test_target "$test_path"
done

echo "All requested tests finished successfully."
