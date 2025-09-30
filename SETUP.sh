#!/usr/bin/env bash
# Setup script for building liboqs
    
echo "MUST BE RUN FROM liboqs ROOT DIRECTORY"

# Delete build directory if it exists
rm -rf build

cmake -GNinja $CMAKE_PARAMS -S . -B build -DCMAKE_INSTALL_PREFIX=build
cd build
ninja -j$(nproc)
ninja install
cd ..

echo "liboqs build complete."
