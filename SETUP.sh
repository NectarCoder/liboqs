#!/usr/bin/env bash
# Setup script for building liboqs

echo "MUST BE RUN FROM liboqs ROOT DIRECTORY"

mkdir -p build
cd build
cmake ..
make -j$(nproc)

echo "liboqs build complete."
