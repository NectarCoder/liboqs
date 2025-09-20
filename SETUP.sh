#!/usr/bin/env bash

echo "MUST BE RUN FROM liboqs ROOT DIRECTORY"

# Setup script for building liboqs
sudo apt-get install build-essential cmake ninja-build libssl-dev

mkdir -p build
cd build
cmake ..
make -j4

echo "liboqs build complete."
