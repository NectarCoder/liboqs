# RYDE

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: TODO.
- **Principal submitters**: TODO.
- **Authors' website**: TODO.
- **Specification version**: TODO.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: TODO
  - **Implementation license (SPDX-Identifier)**: TODO

## Parameter set summary

| Parameter set       | Parameter set alias | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:--------------------|:--------------------|:---------------|--------------------:|------------------------:|------------------------:|-----------------------:|
| RYDE-1S             | NA                  | EUF-CMA        |                   1 |                      69 |                      32 |                  3115 |
| RYDE-3S             | NA                  | EUF-CMA        |                   3 |                     101 |                      48 |                  7064 |
| RYDE-5S             | NA                  | EUF-CMA        |                   5 |                     132 |                      64 |                 12607 |

## RYDE-3S implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## RYDE-1S implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
