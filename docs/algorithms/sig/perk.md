# PERK

- **Algorithm type**: Digital signature scheme.
- **Main cryptographic assumption**: Permuted Kernel Problem (PKP).
- **Principal submitters**: Najwa AARAJ, Slim BETTAIEB, Loic BIDOUX, Alessandro BUDRONI, Victor DYSERYN, Andre ESSER, Thibauld FENEUIL, Philippe GABORIT, Mukul KULKARNI, Victor MATEU, Marco PALUMBI, Lucas PERIN, Matthieu RIVAIN, Jean-Pierre TILLICH, Keita XAGAWA.
- **Authors' website**: TODO.
- **Specification version**: v2.2.0.
- **Primary Source**<a name="primary-source"></a>:
  - **Source**: src/round2bin/perk_v2.2.0/Reference_Implementation with liboqs integration patches
  - **Implementation license (SPDX-Identifier)**: CC0-1.0

## Parameter set summary

|  Parameter set   | Parameter set alias   | Security model   |   Claimed NIST Level |   Public key size (bytes) |   Secret key size (bytes) |   Signature size (bytes) |
|:----------------:|:----------------------|:-----------------|---------------------:|--------------------------:|--------------------------:|-------------------------:|
| PERK-AK-1-short | NA | EUF-CMA | 1 | 104 | 120 | 3473 |
| PERK-AES-AES-1-short | NA | EUF-CMA | 1 | 104 | 120 | 3473 |
| PERK-KECCAK-KECCAK-1-short | NA | EUF-CMA | 1 | 104 | 120 | 3473 |
| PERK-AK-3-short | NA | EUF-CMA | 3 | 151 | 175 | 8311 |
| PERK-AES-AES-3-short | NA | EUF-CMA | 3 | 151 | 175 | 8311 |
| PERK-KECCAK-KECCAK-3-short | NA | EUF-CMA | 3 | 151 | 175 | 8311 |
| PERK-AK-5-short | NA | EUF-CMA | 5 | 195 | 227 | 14830 |
| PERK-AES-AES-5-short | NA | EUF-CMA | 5 | 195 | 227 | 14830 |
| PERK-KECCAK-KECCAK-5-short | NA | EUF-CMA | 5 | 195 | 227 | 14830 |

## Implementation characteristics

|  Parameter set   |       Implementation source       | Identifier in upstream   | Supported architecture(s)   | Supported operating system(s)   | CPU extension(s) used   | No branching-on-secrets claimed?   | No branching-on-secrets checked by valgrind?   | Large stack usage?   |
|:----------------:|:---------------------------------:|:-------------------------|:----------------------------|:--------------------------------|:------------------------|:-----------------------------------|:-----------------------------------------------|:---------------------|
| PERK-AK-1-short  | [Primary Source](#primary-source) | aes_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AES-AES-1-short  | [Primary Source](#primary-source) | aes_aes_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-KECCAK-KECCAK-1-short  | [Primary Source](#primary-source) | keccak_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AK-3-short  | [Primary Source](#primary-source) | aes_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AES-AES-3-short  | [Primary Source](#primary-source) | aes_aes_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-KECCAK-KECCAK-3-short  | [Primary Source](#primary-source) | keccak_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AK-5-short  | [Primary Source](#primary-source) | aes_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-AES-AES-5-short  | [Primary Source](#primary-source) | aes_aes_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |
| PERK-KECCAK-KECCAK-5-short  | [Primary Source](#primary-source) | keccak_keccak_short         | TODO                        | TODO                            | TODO                    | TODO                               | TODO                                           | TODO                 |

Are implementations chosen based on runtime CPU feature detection? **No**.

## Explanation of Terms

- **Large Stack Usage**: Implementations identified as having such may cause failures when running in threads or in constrained environments.
