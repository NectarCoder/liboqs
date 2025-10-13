# MQOM

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: Hardness of solving random multivariate quadratic systems over GF(2).
- **Principal submitters**: Ryad Benadjila, Charles Bouillaguet, Thibauld Feneuil, Matthieu Rivain.
- **Authors' website**: https://mqom.org.
- **Specification version**: 2.0 (February 5, 2025).
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: src/sig/mqom/mqom2_cat1_gf2_short_r3/lib
  - **Source**: src/sig/mqom/mqom2_cat1_gf16_short_r3/lib
  - **Source**: src/sig/mqom/mqom2_cat1_gf16_short_r5/lib
  - **Source**: src/sig/mqom/mqom2_cat1_gf256_short_r3/lib
  - **Source**: src/sig/mqom/mqom2_cat1_gf256_short_r5/lib
  - **Implementation license (SPDX-Identifier)**: CC0-1.0

## Parameter set summary

| Parameter set                | Parameter set alias | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:-----------------------------|:--------------------|:---------------|--------------------:|------------------------:|------------------------:|-----------------------:|
| MQOM2-CAT1-GF2-SHORT-R3      | NA                  | EUF-CMA        |                   1 |                      52 |                      72 |                  2868 |
| MQOM2-CAT1-GF2-SHORT-R5      | NA                  | EUF-CMA        |                   1 |                      52 |                      72 |                  2820 |
| MQOM2-CAT1-GF16-SHORT-R3     | NA                  | EUF-CMA        |                   1 |                      60 |                      88 |                  3060 |
| MQOM2-CAT1-GF16-SHORT-R5     | NA                  | EUF-CMA        |                   1 |                      60 |                      88 |                  2916 |
| MQOM2-CAT1-GF256-SHORT-R3    | NA                  | EUF-CMA        |                   1 |                      80 |                     128 |                  3540 |
| MQOM2-CAT1-GF256-SHORT-R5    | NA                  | EUF-CMA        |                   1 |                      80 |                     128 |                  3156 |

## MQOM2-CAT1-GF2-SHORT-R3 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

## MQOM2-CAT1-GF2-SHORT-R5 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

## MQOM2-CAT1-GF16-SHORT-R3 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

## MQOM2-CAT1-GF16-SHORT-R5 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

## MQOM2-CAT1-GF256-SHORT-R3 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

## MQOM2-CAT1-GF256-SHORT-R5 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | False                              | False                                             | True                |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
