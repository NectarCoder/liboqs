# SQIsign

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: Hardness of computing isogenies between supersingular elliptic curves (SQI assumption).
- **Principal submitters**: SQIsign team (per NIST Round 2 additional signature submission).
- **Authors' website**: https://sqisign.org/
- **Specification version**: 2025-07-07.
- **Primary Source**<a name="primary-source"></a>:
	- **Source**: sqisign-ref-impl
	- **Implementation license (SPDX-Identifier)**: Apache-2.0

## Parameter set summary

| Parameter set   | Parameter set alias | Security model | Claimed NIST Level | Public key size (bytes) | Secret key size (bytes) | Signature size (bytes) |
|:----------------|:--------------------|:---------------|--------------------:|------------------------:|------------------------:|-----------------------:|
| SQIsign-353     | NIST Level I        | EUF-CMA        |                   1 |                      65 |                     353 |                    148 |
| SQIsign-529     | NIST Level III      | EUF-CMA        |                   3 |                      97 |                     529 |                    224 |
| SQIsign-701     | NIST Level V        | EUF-CMA        |                   5 |                     129 |                     701 |                    292 |

## SQIsign-353 implementation characteristics

|       Implementation source       | Identifier in upstream | Supported architecture(s) | Supported operating system(s) | CPU extension(s) used | No branching-on-secrets claimed? | No branching-on-secrets checked by valgrind? | Large stack usage? |
|:---------------------------------:|:-----------------------|:--------------------------|:------------------------------|:----------------------|:---------------------------------|:---------------------------------------------|:-------------------|
| Reference implementation          | ref                    | Generic C (64-bit)        | Cross-platform                | None                 | Unknown                         | Unknown                                       | Unknown            |

## SQIsign-529 implementation characteristics

|       Implementation source       | Identifier in upstream | Supported architecture(s) | Supported operating system(s) | CPU extension(s) used | No branching-on-secrets claimed? | No branching-on-secrets checked by valgrind? | Large stack usage? |
|:---------------------------------:|:-----------------------|:--------------------------|:------------------------------|:----------------------|:---------------------------------|:---------------------------------------------|:-------------------|
| Reference implementation          | ref                    | Generic C (64-bit)        | Cross-platform                | None                 | Unknown                         | Unknown                                       | Unknown            |

## SQIsign-701 implementation characteristics

|       Implementation source       | Identifier in upstream | Supported architecture(s) | Supported operating system(s) | CPU extension(s) used | No branching-on-secrets claimed? | No branching-on-secrets checked by valgrind? | Large stack usage? |
|:---------------------------------:|:-----------------------|:--------------------------|:------------------------------|:----------------------|:---------------------------------|:---------------------------------------------|:-------------------|
| Reference implementation          | ref                    | Generic C (64-bit)        | Cross-platform                | None                 | Unknown                         | Unknown                                       | Unknown            |