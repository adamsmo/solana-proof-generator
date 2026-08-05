#!/usr/bin/env bash

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-${repo_dir}/target}"

export CARGO_TARGET_DIR="${target_dir}"

host_tests() {
  cargo test -p halo2-solana-verifier --features std,solana-syscalls
  RUSTC_BOOTSTRAP=1 cargo test -p halo2-solana-vk-host --lib
  RUSTC_BOOTSTRAP=1 cargo test -p shielded-pool-circuit --lib --test fixture_verifies
  cargo test -p shielded-pool-solana-verifier --lib
}

generate_fixtures() {
  RUSTC_BOOTSTRAP=1 cargo run --release \
    -p shielded-pool-circuit \
    --bin generate-shielded-pool-fixture \
    -- "${repo_dir}/fixtures"
}

build_sbf() {
  local sbf_rustc="${SBF_RUSTC:-}"
  local candidate

  if [[ -z "${sbf_rustc}" ]]; then
    for candidate in "${RUSTUP_HOME:-${HOME}/.rustup}"/toolchains/*-sbpf-solana-*/bin/rustc; do
      if [[ -x "${candidate}" ]]; then
        sbf_rustc="${candidate}"
      fi
    done
  fi

  if [[ -n "${sbf_rustc}" ]]; then
    RUSTC="${sbf_rustc}" cargo build-sbf \
      --manifest-path "${repo_dir}/programs/shielded-pool-verifier/Cargo.toml" \
      --features bpf-entrypoint \
      --no-rustup-override
  else
    cargo build-sbf \
      --manifest-path "${repo_dir}/programs/shielded-pool-verifier/Cargo.toml" \
      --features bpf-entrypoint
  fi
}

svm_tests() {
  local program_path="${target_dir}/deploy/shielded_pool_solana_verifier.so"
  if [[ ! -f "${program_path}" ]]; then
    echo "missing ${program_path}; run ./scripts/verify.sh sbf first" >&2
    exit 1
  fi

  SBF_OUT_DIR="${target_dir}/deploy" \
    cargo test -p shielded-pool-solana-verifier \
      --features svm-test \
      --test svm \
      -- --nocapture
}

case "${1:-all}" in
  host)
    host_tests
    ;;
  generate)
    generate_fixtures
    ;;
  sbf)
    build_sbf
    ;;
  svm)
    svm_tests
    ;;
  all)
    generate_fixtures
    host_tests
    build_sbf
    svm_tests
    ;;
  *)
    echo "usage: $0 [host|generate|sbf|svm|all]" >&2
    exit 2
    ;;
esac
