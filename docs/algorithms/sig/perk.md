# PERK

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: TODO.
- **Principal submitters**: TODO.
- **Authors' website**: TODO.
- **Specification version**: v2.1.0.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: TODO
  - **Implementation license (SPDX-Identifier)**: TODO

## Parameter set summary

|  Parameter set   | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:----------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
| PERK-AK-1-short | NA | EUF-CMA | 1 | 104 | 120 | 3473 |
| PERK-AK-3-short | NA | EUF-CMA | 3 | 151 | 175 | 8311 |
| PERK-AK-5-short | NA | EUF-CMA | 5 | 195 | 227 | 14830 |

## Implementation characteristics

|  Parameter set   |       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:----------------:|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| PERK-AK-1-short  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AK-3-short  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AK-5-short  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
