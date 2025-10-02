# PERK

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
| PERK-128-fast-3     | NA                  | EUF-CMA        |                   1 |                     148 |                     164 |                   8345 |
| PERK-128-short-3    | NA                  | EUF-CMA        |                   1 |                     148 |                     164 |                   6251 |
| PERK-128-short-5    | NA                  | EUF-CMA        |                   1 |                     241 |                     257 |                   5780 |
| PERK-192-short-3    | NA                  | EUF-CMA        |                   1 |                     227 |                     251 |                  14280 |
| PERK-192-short-5    | NA                  | EUF-CMA        |                   1 |                     368 |                     392 |                  13164 |
| PERK-256-short-3    | NA                  | EUF-CMA        |                   1 |                     314 |                     346 |                  25141 |
| PERK-256-short-5    | NA                  | EUF-CMA        |                   1 |                     507 |                     539 |                  23040 |

## PERK-128-fast-3 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## PERK-128-short-3 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
