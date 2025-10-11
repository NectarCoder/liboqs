# MIRATH

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: TODO.
- **Principal submitters**: TODO.
- **Authors' website**: TODO.
- **Specification version**: TODO.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: TODO
  - **Implementation license (SPDX-Identifier)**: TODO

## Parameter set summary

| Parameter set               | Parameter set alias | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:----------------------------|:--------------------|:---------------|--------------------:|------------------------:|------------------------:|-----------------------:|
| MIRATH-TCITH-1A-SHORT       | NA                  | EUF-CMA        |                   1 |                      73 |                      32 |                  3182 |
| MIRATH-TCITH-1B-SHORT       | NA                  | EUF-CMA        |                   1 |                      57 |                      32 |                  2990 |
| MIRATH-TCITH-3A-SHORT       | NA                  | EUF-CMA        |                   3 |                     107 |                      48 |                  7456 |
| MIRATH-TCITH-3B-SHORT       | NA                  | EUF-CMA        |                   3 |                      84 |                      48 |                  6825 |
| MIRATH-TCITH-5A-SHORT       | NA                  | EUF-CMA        |                   5 |                     147 |                      64 |                 13091 |
| MIRATH-TCITH-5B-SHORT       | NA                  | EUF-CMA        |                   5 |                     112 |                      64 |                 12229 |

## MIRATH-TCITH-1A-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (1A-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

## MIRATH-TCITH-1B-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (1B-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

## MIRATH-TCITH-3A-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (3A-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

## MIRATH-TCITH-3B-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (3B-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

## MIRATH-TCITH-5A-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (5A-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

## MIRATH-TCITH-5B-SHORT implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref (5B-short)           | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
