# Sammati
Sammati - Account Aggregator API version 2.1.0
The first open-source reference implementation of ReBIT AA and FIP APIs.
Implemented in Rust for efficiency and security.

ReBIT specifications can be found at:
    https://api.rebit.org.in/
    https://api.rebit.org.in/viewSpec/AA_2_1_0.yaml

This source code MUST NOT be used for production purposes.

We believe that in a large democractic country like ours, we should encourage
open source implementations of banking and finance APIs.

This version of Sammati
   - can be used for understanding the AA-FIP APIs and their architecture.
   - includes unit tests.
   - mocks FIP endpoints.
   - demonstrates best practices in the context of ECDHE and HKDF.
   - offers choices: AES-GCM and CHACHA20POLY1305 data encrytion algorithms.
   - shows the correct use of detached signatures.
   - and much more!

