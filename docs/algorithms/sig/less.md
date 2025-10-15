# LESS

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: multivariable cryptography.
- **Principal submitters**: Placeholder Submitter.
- **Authors' website**: https://example.com
- **Specification version**: Round 2.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: https://github.com/example/LESS
  - **Implementation license (SPDX-Identifier)**: MIT


## Parameter set summary

|        Parameter set        | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:---------------------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
|         LESS-252-192        | NA                    | EUF-CMA          |                    1 |                     13940 |                        32 |                     2625 |
|         LESS-252-68         | NA                    | EUF-CMA          |                    1 |                     41788 |                        32 |                     1825 |
|         LESS-252-45         | NA                    | EUF-CMA          |                    1 |                     97484 |                        32 |                     1329 |
|        LESS-400-220         | NA                    | EUF-CMA          |                    3 |                     35074 |                        48 |                     6329 |
|        LESS-400-102         | NA                    | EUF-CMA          |                    3 |                    105174 |                        48 |                     4131 |
|        LESS-548-345         | NA                    | EUF-CMA          |                    5 |                     65793 |                        64 |                    10680 |
|        LESS-548-137         | NA                    | EUF-CMA          |                    5 |                    197315 |                        64 |                     7436 |

## LESS-252-192 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | False                 |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-252-68 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | False                 |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-252-45 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | False                 |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | False                 |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-400-220 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | True                  |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-400-102 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | True                  |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-548-345 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | True                  |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## LESS-548-137 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | opt                      | All                         | All                             | None                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | avx2                     | x86_64                      | Linux                           | AVX2                    | True                               | True                                           | True                  |
| [Primary Source](#primary-source) | neon                     | ARM64_V8                    | Linux                           | None                    | True                               | True                                           | True                  |

Are implementations chosen based on runtime CPU feature detection? **Yes**.

## Explanation of Terms

- **Implementation license**: The license under which the implementation is released.
- **No branching-on-secrets claimed?**: Does the implementation claim to not have branches (if statements) that depend on secret information?
- **No branching-on-secrets checked by valgrind?**: Has the implementation been checked with valgrind to confirm the absence of branches on secret information?
- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.