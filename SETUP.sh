#!/usr/bin/env bash
# Setup script for building liboqs
    
echo "MUST BE RUN FROM liboqs ROOT DIRECTORY"

# Clean
rm -rf build
rm -rf tmp
rm -rf .pytest_cache

# Do not use AXV2, AVX512, AVX, or ARM NEON instructions
export CMAKE_PARAMS="${CMAKE_PARAMS:+$CMAKE_PARAMS } -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
-DOQS_USE_AVX2_INSTRUCTIONS=OFF -DOQS_USE_AVX512_INSTRUCTIONS=OFF \
-DOQS_USE_AVX_INSTRUCTIONS=OFF -DOQS_USE_ARM_NEON_INSTRUCTIONS=OFF \
-DCMAKE_C_FLAGS=\"-O1\""
export CFLAGS="-O1"
export CXXFLAGS="$CFLAGS" 
export OSSL_CONFIG="no-asm"

# Build
cmake -GNinja $CMAKE_PARAMS -S . -B build -DCMAKE_INSTALL_PREFIX=build
cd build
ninja -j$(nproc)
ninja install
cd ..

echo "liboqs build complete."
