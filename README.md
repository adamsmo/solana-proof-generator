# Halo2 Solana verifier

This repository verifies a Halo2 BN254/KZG proof with the GWC multi-opening scheme inside a Solana SBF program. It also contains the exact off-chain circuit and generator used to create the checked-in proof, VK and KZG verifier key.

The on-chain program does not store nullifiers, update a Merkle root, move funds or manage application state. That logic belongs in the calling Solana program.

## AI-assisted integration

This repository was assembled with help from OpenAI GPT-5.6 Sol. The model was used as an integration and translation assistant: connecting existing Halo2, BN254/KZG, Rust and Solana components, translating existing verifier logic and binary layouts from earlier Aiken/Haskell work into Rust and Solana SBF conventions, explaining the code, and helping with glue code, tests and documentation.

The circuit statement and cryptographic algorithms were not invented by the model. They come from the existing circuit, Halo2/KZG implementations and Solana BN254 runtime interface referenced by the code.

## Complete local test flow

With Rust and the Solana SBF toolchain installed, this repository runs the complete reproducible test flow with one command:

```sh
./scripts/verify.sh all
```

The command runs these steps in order:

1. Generates deterministic test KZG parameters, PK, VK, and the proof and public inputs for withdrawal steps 0, 1 and 2.
2. Compiles the Halo2 VK into the flat format used by the Solana verifier.
3. Verifies the generated proof on the host.
4. Runs the verifier, circuit, VK compiler and fixture tests.
5. Builds the Solana SBF program with the generated VK and KZG VK embedded in it.
6. Runs the program inside Mollusk and reaches the final BN254 pairing check.
7. Runs the proof and public-input tamper tests.

All project-specific source needed for this test flow is in this repository. On the first build, Cargo downloads the locked crates and pinned Git dependencies from `Cargo.lock`. Rust, Git, a native linker and the Solana toolchain are installed separately.

This flow generates and verifies the checked-in test witness. It does not deploy the program to a cluster, accept an arbitrary witness through a CLI, or implement nullifier storage and payouts.

## Requirements

- macOS, Linux or Windows through WSL
- Rust and Cargo through [rustup](https://www.rust-lang.org/tools/install)
- [Solana CLI](https://solana.com/docs/intro/installation/dependencies), including `cargo-build-sbf`
- Git and internet access for the first Cargo dependency download
- a native C compiler and linker: Xcode Command Line Tools on macOS or `build-essential` on Ubuntu/Debian

The workspace declares Rust `1.85` as its minimum. The complete flow was tested with:

```text
rustc 1.96.0
cargo 1.96.0
solana-cli 4.0.3
cargo-build-sbf 4.0.0
Solana platform-tools rustc 1.89.0
```

Install the native compiler on macOS:

```sh
xcode-select --install
```

On Ubuntu or Debian:

```sh
sudo apt-get update
sudo apt-get install build-essential git curl
```

Install Rust and the Solana CLI using their linked official instructions, then check the environment:

```sh
rustc --version
cargo --version
git --version
cc --version
solana --version
cargo-build-sbf --version
```

## Repository layout

- `crates/verifier`: `no_std` BN254/GWC verifier and the `verify_gwc` API. On-chain path uses `solana-bn254` plus raw `sol_keccak256` / `sol_big_mod_exp` via `solana-define-syscall` (no `solana-program`, so Quasar/`no_std` callers can link it)
- `programs/shielded-pool-verifier`: minimal SBF wrapper with a pinned circuit VK and KZG VK
- `circuits/shielded-pool`: off-chain circuit, prover and fixture generator
- `crates/vk-host`: off-chain compiler from the Halo2 `VerifyingKey` to the flat on-chain VK format
- `vendor/halo2-base`: source required to build the original circuit and generator
- `fixtures`: generated binary artifacts
- `scripts/verify.sh`: generation, host tests, SBF build and Mollusk tests

The wrapper accepts instruction tag `0` and one read-only account containing a packed `fixture.bin` (for example `fixtures/step0/fixture.bin`). The account contains only the proof and public inputs. The circuit VK and KZG VK are compiled into the SBF program with `include_bytes!`, so a caller cannot replace them with keys for another circuit.

## Generate the binary artifacts

The generator is [`circuits/shielded-pool/src/bin/generate_fixture.rs`](circuits/shielded-pool/src/bin/generate_fixture.rs). Run it from the repository root:

```sh
./scripts/verify.sh generate
```

Equivalent Cargo command:

```sh
RUSTC_BOOTSTRAP=1 cargo run --release \
  -p shielded-pool-circuit \
  --bin generate-shielded-pool-fixture \
  -- fixtures
```

The generator performs these steps:

1. Builds the shielded-pool circuit with `k = 16` and blinding factor `9`.
2. Creates deterministic test KZG parameters with `ParamsKZG::unsafe_setup` and seed `[0x53; 32]`.
3. Generates the Halo2 VK and proving key.
4. Creates a BN254/KZG/GWC proof with the Solana Keccak transcript.
5. Verifies the proof with the native Halo2 verifier.
6. Compiles the VK to the flat format used by the Solana verifier.
7. Verifies the proof with `halo2-solana-verifier` on the host.
8. Writes the proof, public inputs and packed `fixture.bin` to `step{N}/`, and the shared `vk.bin` and `kzg_vk.bin` once.

Steps 1 to 8 run in one loop for each withdrawal step `0`, `1` and `2` of the same deposit. Every step must produce the same circuit VK and KZG VK, otherwise the generator stops. The optional argument is the output directory; it defaults to `fixtures`.

The deterministic setup is for repeatable tests only. Production artifacts must use the production circuit and trusted SRS.

## Generated files

| File | Bytes | Used for |
| --- | ---: | --- |
| `fixtures/vk.bin` | 749 | Circuit-specific verifier protocol. Shared by all steps. Compiled once into the SBF program. |
| `fixtures/kzg_vk.bin` | 320 | Trimmed KZG verifier key: `[1]_1 \|\| [1]_2 \|\| [tau]_2`. Shared by all steps. Compiled once into the SBF program. |
| `fixtures/step{N}/proof.bin` | 1088 | GWC proof for withdrawal step `N`. Changes for each new proof. |
| `fixtures/step{N}/public_inputs.bin` | 160 | Five canonical BN254 scalar field elements, 32 bytes each. |
| `fixtures/step{N}/fixture.bin` | 1264 | Packed proof and public inputs placed in the proof-data account. |

`N` is `0`, `1` or `2`: the three chunk withdrawals of one 9 SOL deposit. The SBF wrapper unit tests and the Mollusk tests use `fixtures/step0/fixture.bin`. See [`fixtures/README.md`](fixtures/README.md) for the witness values of each step.

These sizes were produced by the checked-in generator. A different circuit can produce a different VK or proof size.

The public input order is:

```text
[step, chunk_amount, dest_address, nullifier, root]
```

## Why the VK is binary

The binary VK is the format parsed directly by `crates/verifier/src/vk.rs`. It is compact, deterministic and does not require Borsh, Serde or JSON in the SBF program.

`vk.bin` and `kzg_vk.bin` add 1069 raw bytes to the deployed program data. They are not sent again with every proof. Each step's `fixture.bin` is 1264 bytes. The previous format also carried both keys in the proof-data account and was 2337 bytes, so pinning the keys removes 1073 bytes from each proof payload.

The verifier still parses the pinned VK during each verification. The binary format keeps that parser small and avoids a general-purpose serialization layer. Replacing it with Rust constants would not remove the cryptographic work and would make the generated interface harder to audit.

For a new proof using the same circuit and SRS, regenerate only the proof and public inputs. If the circuit shape or SRS changes, regenerate all artifacts, rebuild the SBF program and redeploy it because the pinned keys change.

## Proof account format

Lengths are little-endian. Proof bytes, field elements and curve coordinates use the formats expected by the verifier.

```text
"H2PF0001"                  8 bytes
proof_len                   u32
proof                       proof_len bytes
public_input_count          u32
public_inputs               public_input_count * 32 bytes
```

For the checked-in vector this is `8 + 4 + 1088 + 4 + 160 = 1264` bytes.

## Integration boundary

There are two ways to use the verifier.

### Link the verifier crate into your program

Add a path dependency:

```toml
[dependencies]
halo2-solana-verifier = { path = "../halo2-solana-verifier/crates/verifier", default-features = false, features = ["solana-syscalls"] }
```

Call it with keys pinned by your application:

```rust
let accepted = halo2_solana_verifier::verify_gwc(
    pinned_vk,
    proof,
    public_inputs,
    &pinned_kzg_vk,
)
.map_err(|_| MyProgramError::ProofVerifierFailed)?;

if !accepted {
    return Err(MyProgramError::InvalidProof.into());
}
```

The application must also pin the public input schema. The verifier checks only the proof equation and cannot decide what each field means.

### Call the minimal verifier program through CPI

The application creates or validates the proof-data account, binds the five public inputs to its instruction and state, invokes the included verifier program, and continues only when the CPI succeeds.

The calling program remains responsible for nullifier state, accepted roots, destination binding and payout.

## Verification commands

Run host tests, including the checked-in proof:

```sh
./scripts/verify.sh host
```

Regenerate the shared VKs and the proof, public inputs and packed fixture of every step:

```sh
./scripts/verify.sh generate
```

Build the SBF program:

```sh
./scripts/verify.sh sbf
```

If `cargo-build-sbf` cannot locate its Rust compiler, set `SBF_RUSTC` to the `rustc` binary from the installed `*-sbpf-solana-*` toolchain.

Run the proof and tamper tests inside Mollusk:

```sh
./scripts/verify.sh svm
```

Regenerate all artifacts, run host tests, build SBF and run Mollusk tests:

```sh
./scripts/verify.sh all
```

The SVM suite covers a valid proof, changed public inputs, changed proof data, invalid point encoding, malformed lengths, trailing bytes and a non-canonical field element. It also checks the final pairing path and verifies that the valid fixture fits the 1,400,000 CU limit configured by the test harness.

## Solana syscall mode

The default build uses the big-endian BN254 syscall wrappers. The optional `simd-0284-le` feature switches the syscall boundary to the little-endian variants. Enable it only when the target runtime has that feature active.

Solana references:

- [Program execution and compute budget](https://solana.com/docs/core/programs/program-execution)
- [Syscall reference](https://solana.com/docs/core/programs/syscall-reference)

## License

Licensed under MIT or Apache-2.0. Original and vendored notices are listed in [NOTICE.md](NOTICE.md).
