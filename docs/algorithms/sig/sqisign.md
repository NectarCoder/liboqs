# SQIsign

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: Isogeny.
- **Principal submitters**: TODO.
- **Authors' website**: TODO.
- **Specification version**: TODO.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: TODO
  - **Implementation license (SPDX-Identifier)**: TODO

## Parameter set summary

|  Parameter set   | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:----------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
| SQIsign-353 | NA | EUF-CMA | 1 | 65 | 353 | 148 |
| SQIsign-529 | NA | EUF-CMA | 3 | 97 | 529 | 224 |
| SQIsign-701 | NA | EUF-CMA | 5 | 129 | 701 | 292 |

## Implementation characteristics

|  Parameter set   |       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:----------------:|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| SQIsign-353  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| SQIsign-529  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| SQIsign-701  | [Primary Source](#primary-source) | ref                      | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
