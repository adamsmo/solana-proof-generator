# Security boundary

The verifier answers one question: does this proof verify against this VK, KZG VK and list of public inputs?

It does not decide whether a nullifier was already used, whether a Merkle root is accepted by the application, whether a destination account is correct or whether a payout should happen.

The minimal SBF wrapper pins the checked-in VK and KZG VK. A program that calls `verify_gwc` directly must provide the same protection itself. It must also bind every public input to the application instruction and account state before making any state change.

The checked-in test vector and `generate-shielded-pool-fixture` binary use deterministic `ParamsKZG::unsafe_setup`. They exist only for repeatable tests. Replace the setup step with the production trusted SRS, then regenerate the VK, KZG VK and proof before using the verifier with real assets.

The SBF wrapper embeds `fixtures/vk.bin` and `fixtures/kzg_vk.bin` at build time. Any circuit or SRS change requires regeneration, a new SBF build and redeployment. A new proof for the unchanged circuit and SRS does not require redeployment.

This code has not been independently audited.
