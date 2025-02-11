#!/usr/bin/env bash
CURRENT_COMMIT=$(git rev-parse HEAD)
PREVIOUS_VERSION=$(git describe --tags --abbrev=0 $CURRENT_COMMIT)

BUILD_DIR=_build_for_is_abi_compatible

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
if [ "$CURRENT_COMMIT" = "$(git rev-parse master)" ]; then
  git checkout -q  master
else
  git checkout -q "${CURRENT_COMMIT}"
fi

# ABI compatibility check
../check-abi-compatibility.sh ./old/out/lib/libcpp-httplib.so ./new/out/lib/libcpp-httplib.so

# Clean the build directory
cd ..
rm -rf $BUILD_DIR
