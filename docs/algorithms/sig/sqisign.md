# SQIsign

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: Isogeny-based (related to SIDH).
- **Principal submitters**: Luca De Feo, Antonin Leroux, Pierrick Dartois, Javier Silva, Christophe Petit.
- **Authors' website**: https://sqisign.org/
- **Specification version**: 2.0.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: https://github.com/SQISign/sqisign-framework
  - **Implementation license (SPDX-Identifier)**: Apache-2.0

## Parameter set summary

| Parameter set       | Parameter set alias | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:--------------------|:--------------------|:---------------|--------------------:|------------------------:|------------------------:|-----------------------:|
| SQIsign-353         | NA                  | EUF-CMA        |                   1 |                      65 |                     353 |                    148 |
| SQIsign-529         | NA                  | EUF-CMA        |                   3 |                      97 |                     529 |                    224 |
| SQIsign-701         | NA                  | EUF-CMA        |                   5 |                     129 |                     701 |                    292 |

## SQIsign-353 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | No                                 | No                                             | No                   |

## SQIsign-529 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | No                                 | No                                             | No                   |

## SQIsign-701 implementation characteristics

|       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| [Primary Source](#primary-source) | ref                      | All                         | All                             | None                    | No                                 | No                                             | No                   |
