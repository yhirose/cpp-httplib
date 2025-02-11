#!/usr/bin/env bash
PREVIOUS_VERSION=$(git describe --tags --abbrev=0 master)
BUILD_DIR=_build_for_abi_compatibility_check

# Make the build directory
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/new
mkdir -p $BUILD_DIR/old

cd $BUILD_DIR

# Build the current commit
cd new

cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-g -Og" \
  -DBUILD_SHARED_LIBS=ON \
  -DHTTPLIB_COMPILE=ON \
  -DCMAKE_INSTALL_PREFIX=./out \
  ../../.. > /dev/null

cmake --build . --target install > /dev/null
cmake --build . --target clean > /dev/null

cd ..

# Build the nearest vesion
cd old

cmake \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-g -Og" \
  -DBUILD_SHARED_LIBS=ON \
  -DHTTPLIB_COMPILE=ON \
  -DCMAKE_INSTALL_PREFIX=./out \
  ../../.. > /dev/null

git checkout -q "${PREVIOUS_VERSION}"
cmake --build . --target install > /dev/null
cmake --build . --target clean > /dev/null

cd ..

# Checkout the original commit
git checkout -q  master

# ABI compatibility check
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  ../check-abi-compatibility.sh ./old/out/lib/libcpp-httplib.so ./new/out/lib/libcpp-httplib.so
  exit $?
elif [[ "$OSTYPE" == "darwin"* ]]; then
  ../check-abi-compatibility.sh ./old/out/lib/libcpp-httplib.dylib ./new/out/lib/libcpp-httplib.dylib
  exit $?
else
  echo "Unknown OS..."
  exit 1
fi
