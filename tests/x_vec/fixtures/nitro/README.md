# Historical AWS-signed attestation fixture

`aws-2025-01-06.cose` is the 4,781-byte public fixture from the published
`nitro_attest` 0.2.0 crate, `tests/fixtures/attestation.cose`.
Source: https://crates.io/crates/nitro_attest/0.2.0
Repository: https://github.com/aws-nitro-enclaves/nitro-attest

It is used only to test the AWS certificate profile and COSE signature at the
historical Unix time 1736179625. Its certificates are expired today, and it lacks
our required owner nonce/context. It is not live attestation of the BFV service.
No private keys are included. The fixture is redistributed under the upstream
MIT license (Joern Barthel, 2025); see the adjacent `LICENSE` file.
