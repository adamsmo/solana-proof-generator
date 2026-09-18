# Generated test artifacts

All files in this directory are created by `circuits/shielded-pool/src/bin/generate_fixture.rs`:

```sh
./scripts/verify.sh generate
```

```text
fixtures/vk.bin
fixtures/kzg_vk.bin
fixtures/step0/{proof.bin,public_inputs.bin,fixture.bin}
fixtures/step1/{proof.bin,public_inputs.bin,fixture.bin}
fixtures/step2/{proof.bin,public_inputs.bin,fixture.bin}
```

| File | Bytes | Contents and consumer |
| --- | ---: | --- |
| `vk.bin` | 749 | Flat circuit verifier protocol parsed by `crates/verifier/src/vk.rs` and embedded in the SBF wrapper. Shared by all steps. |
| `kzg_vk.bin` | 320 | `[1]_1` as 64 bytes, `[1]_2` as 128 bytes and `[tau]_2` as 128 bytes. Embedded in the SBF wrapper. Shared by all steps. |
| `step{N}/proof.bin` | 1088 | BN254/KZG/GWC proof for withdrawing chunk `N` of the fixture deposit. |
| `step{N}/public_inputs.bin` | 160 | Five 32-byte canonical BN254 scalar field elements for that proof. |
| `step{N}/fixture.bin` | 1264 | Proof-account payload for that step. It does not duplicate either verifier key. The SBF wrapper unit tests and Mollusk tests use `step0/fixture.bin`. |

Every step is generated, host-verified and written by the same loop, from `build_fixture_input_for_step(N)` for `N` in `0..MAX_CHUNKS`. The witness is the same for all steps except for the step, so all steps verify with the same `vk.bin` and `kzg_vk.bin` and have the same root. The keys are written once from step 0, and the generator stops if any later step produces a different key. The pool program's tests use all three steps to check that the full 9 SOL is paid out.

Public input order:

```text
[step, chunk_amount, dest_address, nullifier, root]
```

## Witness values

The values come from `build_fixture_input_for_step` in `circuits/shielded-pool/src/circuit/prover.rs`:

| Value | Setting |
| --- | --- |
| secret `s` | `1_234_567_890` |
| total amount | `9_000_000_000` lamports |
| chunks | `[2_000_000_000, 3_000_000_000, 4_000_000_000]` lamports |
| destinations | `dstH17g8RBGdUo3YeYhSFHDdFzHrWkAzNCKSveAchyD` for all three chunks. Each is mapped to a field value with `convert_pubkey_32bytes_to_fr`. |
| step | `0`, `1` and `2`, one per directory |
| tree | depth 20. The deposit commitment is the only leaf, at index 0. |
| setup and prover seed | `[0x53; 32]` |

So the public inputs of step `N` are step `N`, chunk amount `chunks[N]`, the hash of the destination key, `nullifier = Poseidon(s, N)`, and the depth-20 root shared by all steps:

| Directory | step | chunk_amount (lamports) | nullifier |
| --- | ---: | ---: | --- |
| `step0` | `0` | `2_000_000_000` | `Poseidon(s, 0)` |
| `step1` | `1` | `3_000_000_000` | `Poseidon(s, 1)` |
| `step2` | `2` | `4_000_000_000` | `Poseidon(s, 2)` |

Using one key for all three chunks means this fixture does not test choosing between different destinations. The circuit tests in `full_circuit.rs` and `tests/gwc_end_to_end.rs` use three different destinations for that.

`tests/fixture_verifies.rs` checks, for every step, that the proof verifies with the shared keys, that `public_inputs.bin` matches these values, and that `fixture.bin` packs exactly that step's proof and public inputs. Changing the values or the witness does not change `vk.bin` or `kzg_vk.bin`, because the circuit and the setup seed stay the same.

`fixture.bin` format:

```text
"H2PF0001"                  8 bytes
proof_len                   u32 little-endian
proof                       proof_len bytes
public_input_count          u32 little-endian
public_inputs               public_input_count * 32 bytes
```

The generator uses deterministic `ParamsKZG::unsafe_setup` to make this vector reproducible. These artifacts are test data, not production SRS material.
