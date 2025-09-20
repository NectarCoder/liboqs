#!/usr/bin/env bash
# Setup script for building liboqs

echo "MUST BE RUN FROM liboqs ROOT DIRECTORY"

mkdir -p _build
cd _build
cmake ..
make -j4

echo "liboqs build complete."
