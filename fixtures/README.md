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

`fixture.bin` format:

```text
"H2PF0001"                  8 bytes
proof_len                   u32 little-endian
proof                       proof_len bytes
public_input_count          u32 little-endian
public_inputs               public_input_count * 32 bytes
```

The generator uses deterministic `ParamsKZG::unsafe_setup` to make this vector reproducible. These artifacts are test data, not production SRS material.
