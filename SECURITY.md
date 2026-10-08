# Security boundary

The verifier answers one question: does this proof verify against this VK, KZG VK and list of public inputs?

It does not decide whether a nullifier was already used, whether a Merkle root is accepted by the application, whether a destination account is correct or whether a payout should happen.

The minimal SBF wrapper pins the checked-in VK and KZG VK. A program that calls `verify_gwc` directly must provide the same protection itself. It must also bind every public input to the application instruction and account state before making any state change.

The fixture generator loads the public BN254 KZG SRS from `srs/kzg_bn254_16.srs`, distributed by [Axiom](https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_16.srs).

The SBF wrapper embeds `fixtures/vk.bin` and `fixtures/kzg_vk.bin` at build time. Any circuit or SRS change requires regeneration, a new SBF build and redeployment. A new proof for the unchanged circuit and SRS does not require redeployment.

This code has not been independently audited.
