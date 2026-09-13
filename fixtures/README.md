# Generated test artifacts

All files in this directory are created by `circuits/shielded-pool/src/bin/generate_fixture.rs`:

```sh
./scripts/verify.sh generate
```

| File | Bytes | Contents and consumer |
| --- | ---: | --- |
| `vk.bin` | 749 | Flat circuit verifier protocol parsed by `crates/verifier/src/vk.rs` and embedded in the SBF wrapper. |
| `kzg_vk.bin` | 320 | `[1]_1` as 64 bytes, `[1]_2` as 128 bytes and `[tau]_2` as 128 bytes. Embedded in the SBF wrapper. |
| `proof.bin` | 1088 | BN254/KZG/GWC proof produced for the test witness. |
| `public_inputs.bin` | 160 | Five 32-byte canonical BN254 scalar field elements. |
| `fixture.bin` | 1264 | Proof-account payload read by the SBF wrapper. It does not duplicate either verifier key. |

Public input order:

```text
[step, chunk_amount, dest_address, nullifier, root]
```

## Witness values

The values come from `build_fixture_input` in `circuits/shielded-pool/src/circuit/prover.rs`:

| Value | Setting |
| --- | --- |
| secret `s` | `1_234_567_890` |
| total amount | `9_000_000_000` lamports |
| chunks | `[2_000_000_000, 3_000_000_000, 4_000_000_000]` lamports |
| destinations | `dstH17g8RBGdUo3YeYhSFHDdFzHrWkAzNCKSveAchyD` for all three chunks. Each is mapped to a field value with `convert_pubkey_32bytes_to_fr`. |
| step | `0` |
| tree | depth 20. The deposit commitment is the only leaf, at index 0. |
| setup and prover seed | `[0x53; 32]` |

So the public inputs are step `0`, chunk amount `2_000_000_000`, the hash of the destination key, `nullifier = Poseidon(s, 0)`, and the depth-20 root.

Using one key for all three chunks means this fixture does not test choosing between different destinations. The circuit tests in `full_circuit.rs` and `tests/gwc_end_to_end.rs` use three different destinations for that.

`tests/fixture_verifies.rs` checks that the checked-in `public_inputs.bin` matches these values. Changing the values or the witness does not change `vk.bin` or `kzg_vk.bin`, because the circuit and the setup seed stay the same.

`fixture.bin` format:

```text
"H2PF0001"                  8 bytes
proof_len                   u32 little-endian
proof                       proof_len bytes
public_input_count          u32 little-endian
public_inputs               public_input_count * 32 bytes
```

The generator uses deterministic `ParamsKZG::unsafe_setup` to make this vector reproducible. These artifacts are test data, not production SRS material.
