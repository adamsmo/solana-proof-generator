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
| `step{N}/fixture.bin` | 1264 | Proof-account payload for that step, without either verifier key. SBF wrapper unit tests and Mollusk tamper tests use step 0; a separate Mollusk test verifies all three steps. |

The generator uses `build_fixture_input_for_step(N)` for `N` in `0..MAX_CHUNKS` and the same loaded SRS for every step. All steps use the same private deposit witness and root, while `step`, `chunk_amount` and `nullifier` change. The circuit shape and SRS stay the same, so the verifier keys are shared.

The generator verifies every proof on the host and checks the shared keys before writing any files. It takes the keys from step 0 and writes them once. These fixtures describe the three chunk withdrawals of a 9 SOL deposit; this repository verifies their proofs and does not execute payouts.

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
| fixture proof blinding seed | `[0x53; 32]` |

So the public inputs of step `N` are step `N`, chunk amount `chunks[N]`, the hash of the destination key, `nullifier = Poseidon(s, N)`, and the depth-20 root shared by all steps:

| Directory | step | chunk_amount (lamports) | nullifier |
| --- | ---: | ---: | --- |
| `step0` | `0` | `2_000_000_000` | `Poseidon(s, 0)` |
| `step1` | `1` | `3_000_000_000` | `Poseidon(s, 1)` |
| `step2` | `2` | `4_000_000_000` | `Poseidon(s, 2)` |

Using one key for all three chunks means this fixture does not test choosing between different destinations. The circuit tests in `full_circuit.rs` and `tests/gwc_end_to_end.rs` use three different destinations for that.

`tests/fixture_verifies.rs` checks, for every step, that the proof verifies with the shared keys, that `public_inputs.bin` matches these values, and that `fixture.bin` packs exactly that step's proof and public inputs. Changing witness values does not change `vk.bin` or `kzg_vk.bin` when the circuit shape and SRS stay the same. The fixture blinding seed does not determine the SRS or the verifier keys.

`fixture.bin` format:

```text
"H2PF0001"                  8 bytes
proof_len                   u32 little-endian
proof                       proof_len bytes
public_input_count          u32 little-endian
public_inputs               public_input_count * 32 bytes
```

The generator loads the public BN254 KZG SRS from `srs/kzg_bn254_16.srs`, distributed by [Axiom](https://axiom-crypto.s3.amazonaws.com/challenge_0085/kzg_bn254_16.srs). It uses the IOG Halo2 `RawBytes` format with `k = 16`. Set `SRS_PATH` or pass a second generator argument to select another file. The fixed seed is used only for fixture proof blinding; these artifacts remain test data.

`vk.bin` and `kzg_vk.bin` are shared by steps 0, 1 and 2. Proofs, public inputs and packed fixtures exist only in the `step0`, `step1` and `step2` directories. The `H2PF0001` format above is unchanged.
