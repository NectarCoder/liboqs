LESS Reference Implementation — Build & Test

Prerequisites
- A C compiler (gcc or clang)
- CMake (>= 3.0; newer recommended)
- make / build-essential (or equivalent)
- Optional: OpenSSL development libraries (for NIST KAT targets)
  - Debian/Ubuntu: sudo apt install libssl-dev

Quick build (out-of-source)
Run from the project root (where CMakeLists.txt lives):

```bash
mkdir -p build && cd build
cmake ..
cmake --build . -- -j$(nproc)
```

Build type
- By default CMake configures a Release build. To build Debug:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build . -- -j$(nproc)
```

Run tests
From the `build/` directory:

```bash
ctest --output-on-failure
```

Binaries and naming
After a successful build the following executables are generated in `build/`:
- Benchmarks: `LESS_benchmark_cat_<category>_<target>` (e.g. `LESS_benchmark_cat_252_192`)
- Unit tests: `LESS_test_cat_<category>_<target>` (e.g. `LESS_test_cat_252_192`)
- NIST KAT generators: `LESS_nist_cat_<category>_<target>` (links to OpenSSL)

Build a single target
```bash
cmake --build . --target LESS_test_cat_400_220 -- -j$(nproc)
```

Troubleshooting
- CMake can't find OpenSSL: install `libssl-dev` or pass `-DOPENSSL_ROOT_DIR=/path` and `-DOPENSSL_INCLUDE_DIR=/path/include` to cmake.
- Missing compiler or headers: install `build-essential` (Debian/Ubuntu) or equivalent.
- To reconfigure from scratch: remove the `build/` directory and re-run the cmake commands.
- For verbose build output: `cmake --build . -- VERBOSE=1`

Notes
- The project deliberately uses conservative optimizations (-O1) for the Release reference implementation.
