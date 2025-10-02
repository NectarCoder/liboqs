# liboqs AI Coding Agent Instructions

**IMPORTANT!!!!**
BEFORE ANSWERING ANY QUESTION, ALWAYS CONFIRM BY SAYING THE FOLLOWING AS THE FIRST SENTENCE IN YOUR RESPONSE:  
"I have read the copilot instructions and will follow them."

## Project Overview
This is a **specialized fork** of the Open Quantum Safe (OQS) liboqs library focused on implementing **NIST Round 2 post-quantum cryptography (PQC) digital signature algorithms**. Unlike the main liboqs library, this fork contains experimental Round 2 algorithms under active development.

In essence, the purpose of liboqs is to provide a C library that implements post-quantum cryptographic algorithms, allowing developers to experiment with and integrate these algorithms into their applications. This fork specifically focuses on **integrating** digital signature algorithms from NIST's Round 2 PQC for testing and evaluation.

All the instructions in this document are tailored specifically to integrating newer algorithms to liboqs.

## Critical Build Context

### Quick Start (Essential Commands)
```bash
# From project root - MUST BE RUN IN ORDER:
./SETUP_DEPS.sh          # Install system dependencies (if in doubt run a command to check if all dependencies are installed, but they mostly should be)
./SETUP.sh               # Build with all algorithms (may fail with Mirath)

# If build fails with mirath error use this to build (current known issue):
CMAKE_PARAMS='-DOQS_ENABLE_SIG_MIRATH=OFF -DOQS_ENABLE_SIG_mirath_tcith_1a_fast=OFF' ./SETUP.sh

# Test specific algorithms:
cd test_sig
make clean; make
./test_sig hawk-512      # Example: test HAWK-512 algorithm. List of algorithms in src/sig/sig.h
```

### Architecture & Integrating New Digital Signature Algorithms

As mentioned above, this fork focuses on integrating newer PQC **digital signature algorithms**.  
The original liboqs library has some missing so I'm trying to integrate them myself.  

The following directories/files are the most pertinent for understanding how algorithms from the `src/sig/` directory are integrated and made available via the public OQS API - and some require modifications! (and some don't):  

- `.CMake`
- `src/sig/`
   - Each algorithm has its own subdirectory (e.g., `hawk/`, `dilithium/`, etc.)
      - The already included algorithms use library code from `/src/common/`
      - The list of already included algorithms is: [dilithium, falcon, cross, mayo, ml_dsa, snova, uov, sphincs]
   - But the newer integrations of algorithms HAVE THEIR OWN LIB FOLDER
      - USE `src/sig/perk/perk_128_fast_3` AS A TEMPLATE FOR INTEGRATING NEW ALGORITHMS
      - You need to configure namespace files and CMakeLists.txt files and stuff to force the actual algorithm source files to be compiled against and linked to their own libs
      - Main issue is that the libs for each algorithm already exist in `src/common/` so the linker gets confused unless you namespace the new algorithms and their libs properly
      - Once again `src/sig/perk/perk_128_fast_3` is a great example of how to do this
   - Each algorithm has its own `CMakeLists.txt` file for build integration
   - Each algorithm *variant* has it's own glue code file (e.g., `sig_hawk_512.c` for HAWK-512)
      - So you need to add one new glue code file per algorithm variant
- `src/sig/sig.h`
- `src/sig/sig.c`
- `src/CMakeLists.txt`
- `src/oqs.h`
- `src/oqsconfig.h.cmake`
- `src/liboqs.pc.in`
- `src/Config.cmake.in`

1. **Main API Headers**: `src/oqs.h` includes all public APIs
2. **Algorithm Families**:
   - **Standard algorithms**: `src/sig/` (ML-DSA, Dilithium, Falcon, etc.)
   - **Round 2 Bin folder for raw source that you can completely ignore and has no relvance when building and using liboqs**: `src/round2bin/` (HAWK, PERK, Ryde, etc.) 
   - **Key Encapsulation - not the focus of our fork so can be ignored**: `src/kem/` (ML-KEM, Kyber, etc.)
   - **Stateful signatures - also not the focus of our fork**: `src/sig_stfl/` (XMSS, LMS)

3. **Algorithm Integration Pattern**:
   - Each algorithm has `{alg}/CMakeLists.txt` for build integration
   - Algorithm identifiers defined in `src/sig/sig.h` (e.g., `OQS_SIG_alg_hawk_512`)
   - Enable/disable via CMake: `OQS_ENABLE_SIG_{algorithm}=ON/OFF`

## Build System Specifics

### CMake Configuration Pattern
```bash
# Algorithm control (critical for this fork):
-DOQS_ENABLE_SIG_HAWK=ON          # Enable HAWK family
-DOQS_ENABLE_SIG_hawk_512=ON      # Enable specific variant
-DOQS_ALGS_ENABLED=All            # Include experimental algorithms (default)

# Build types:
-DOQS_DIST_BUILD=ON               # Multi-architecture support (default)
-DOQS_MINIMAL_BUILD="SIG_hawk_512;KEM_ml_kem_768"  # Minimal builds
-DOQS_BUILD_ONLY_LIB=ON           # Library only, no tests
```

### Performance/Testing Infrastructure
- **Test harnesses**: `tests/test_sig.c`, `tests/speed_sig.c`
- **Simple test**: `test_sig/test_sig.c` (custom test directory)
- **KAT generation**: `tests/kat_sig.c` for known answer tests
- **Memory testing**: `tests/test_sig_mem.c`

## Development Patterns

### Algorithm Enable/Disable Pattern
```c
// Check if algorithm is enabled at runtime:
OQS_SIG *sig = OQS_SIG_new("hawk-512");
if (sig == NULL) {
    // Algorithm not enabled in build
}
```

### Common API Usage Pattern
```c
#include <oqs/oqs.h>

OQS_SIG *sig = OQS_SIG_new(algorithm_name);
uint8_t *public_key = malloc(sig->length_public_key);
uint8_t *secret_key = malloc(sig->length_secret_key);
uint8_t *signature = malloc(sig->length_signature);

OQS_SIG_keypair(sig, public_key, secret_key);
OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
```

### Testing Workflow
```bash
# Full test suite:
cd build && ninja run_tests

# Individual algorithm testing:
./build/tests/test_sig {algorithm_name}
./build/tests/speed_sig {algorithm_name}

# Custom test harness:
cd test_sig && make && ./test_sig {algorithm_name}
```

## Critical Gotchas

1. **Mirath Integration**: Currently broken - disable with CMake flags shown above
3. **Memory Management**: All algorithms use `OQS_MEM_malloc/free`, not standard malloc
5. **Build Order**: Always run `SETUP.sh` to build liboqs. If for some reason you want to manually build, use ALL PROCESSORS to build faster (make -j nproc).
