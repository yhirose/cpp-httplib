#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

producer_build="$TMP_DIR/producer-build"
install_prefix="$TMP_DIR/install"
consumer_dir="$TMP_DIR/consumer"
consumer_build="$TMP_DIR/consumer-build"
conflict_build="$TMP_DIR/conflict-build"

mkdir -p "$consumer_dir"

cat > "$consumer_dir/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(httplib_mbedtls_component_consumer LANGUAGES CXX)

find_package(httplib REQUIRED COMPONENTS MbedTLS)

if(NOT HTTPLIB_IS_USING_MBEDTLS)
  message(FATAL_ERROR "HTTPLIB_IS_USING_MBEDTLS must be ON")
endif()

if(NOT httplib_MbedTLS_FOUND)
  message(FATAL_ERROR "httplib_MbedTLS_FOUND must be ON")
endif()

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE httplib::httplib)
EOF

cat > "$consumer_dir/main.cpp" <<'EOF'
#include <httplib.h>
int main() { return 0; }
EOF

# The producer package should configure and install with MbedTLS required.
cmake -S "$ROOT_DIR" -B "$producer_build" -G Ninja \
  -DHTTPLIB_COMPILE=OFF \
  -DHTTPLIB_TEST=OFF \
  -DHTTPLIB_REQUIRE_MBEDTLS=ON \
  -DHTTPLIB_USE_OPENSSL_IF_AVAILABLE=OFF \
  -DCMAKE_BUILD_TYPE=Release

cmake --install "$producer_build" --prefix "$install_prefix"

# The consumer should be able to require the MbedTLS component and link.
cmake -S "$consumer_dir" -B "$consumer_build" -G Ninja \
  -DCMAKE_PREFIX_PATH="$install_prefix" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$consumer_build"

# Enabling both TLS backends at once should fail configuration.
if cmake -S "$ROOT_DIR" -B "$conflict_build" -G Ninja \
  -DHTTPLIB_TEST=OFF \
  -DHTTPLIB_USE_OPENSSL_IF_AVAILABLE=ON \
  -DHTTPLIB_USE_MBEDTLS_IF_AVAILABLE=ON \
  -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1; then
  echo "Expected CMake configure to fail when both OpenSSL and MbedTLS are enabled."
  exit 1
fi

echo "CMake MbedTLS component tests passed."
