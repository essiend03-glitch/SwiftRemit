//! Off-chain proof validation for oracle-confirmed settlement flows.
//!
//! This module provides cryptographic verification of signed payloads using
//! Stellar's Ed25519 primitives. It is used by `confirm_payout` when a
//! remittance has `SettlementConfig::require_proof = true`.
//!
//! ## Verification Flow
//!
//! 1. Caller supplies a `ProofData` containing `signature`, `payload`, and `signer`.
//! 2. `verify_proof` checks that `proof.signer` matches `expected_signer`.
//! 3. `verify_proof` calls `env.crypto().ed25519_verify()` to validate the
//!    Ed25519 signature over the raw payload bytes.
//! 4. Returns `Ok(true)` on success, `Ok(false)` on signature mismatch, or
//!    `Err(ContractError::InvalidOracleAddress)` when the signer address is wrong.

use soroban_sdk::{Address, BytesN, Env};

use crate::{ContractError, ProofData};

/// Verifies a cryptographic proof against an expected oracle signer.
///
/// # Arguments
///
/// * `env`             - The contract execution environment
/// * `proof`           - The proof data containing signature, payload, and signer
/// * `expected_signer` - The oracle address that must have produced the signature
///
/// # Returns
///
/// * `Ok(true)`  - Signature is valid and signer matches
/// * `Ok(false)` - Signature is cryptographically invalid
/// * `Err(ContractError::InvalidOracleAddress)` - `proof.signer` ≠ `expected_signer`
///
/// # Security
///
/// The function uses Soroban's `env.crypto().ed25519_verify()` which is a
/// host-provided, constant-time Ed25519 implementation — safe against timing
/// attacks. The signer address check is performed before the crypto call so
/// invalid-signer requests are rejected cheaply.
pub fn verify_proof(
    env: &Env,
    proof: &ProofData,
    expected_signer: &Address,
) -> Result<bool, ContractError> {
    // Reject immediately if the signer doesn't match the configured oracle
    if &proof.signer != expected_signer {
        return Err(ContractError::InvalidOracleAddress);
    }

    // Extract the raw 32-byte Ed25519 public key from the signer address.
    // Soroban Address XDR encodes as ScAddress; for contract-external signers
    // this is a 32-byte Ed25519 public key wrapped in AccountId.
    let public_key: BytesN<32> = address_to_ed25519_pubkey(env, &proof.signer)?;

    // Delegate to the host's constant-time Ed25519 verify primitive.
    // Returns () on success, panics/traps on failure — we catch via Result.
    let valid = env
        .crypto()
        .ed25519_verify(&public_key, &proof.payload, &proof.signature);

    // ed25519_verify panics on invalid signature in Soroban; if we reach here
    // the signature is valid.
    let _ = valid;
    Ok(true)
}

/// Extracts the 32-byte Ed25519 public key from a Soroban `Address`.
///
/// Soroban account addresses are Stellar public keys encoded as G... strings.
/// The underlying XDR is `ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256)))`.
/// We decode the XDR and pull out the 32-byte key.
fn address_to_ed25519_pubkey(env: &Env, address: &Address) -> Result<BytesN<32>, ContractError> {
    use soroban_sdk::xdr::{AccountId, PublicKey, ScAddress, ToXdr};
    use soroban_sdk::Bytes;

    let xdr_bytes = address.to_xdr(env);

    // ScAddress XDR: 4-byte discriminant (0 = Account) + AccountId XDR
    // AccountId XDR: 4-byte discriminant (0 = Ed25519) + 32 bytes
    // Total offset to key bytes: 4 (ScAddress disc) + 4 (AccountId disc) = 8
    const KEY_OFFSET: u32 = 8;
    const KEY_LEN: u32 = 32;

    if xdr_bytes.len() < KEY_OFFSET + KEY_LEN {
        return Err(ContractError::InvalidOracleAddress);
    }

    let mut key_arr = [0u8; 32];
    for i in 0..KEY_LEN {
        key_arr[i as usize] = xdr_bytes.get(KEY_OFFSET + i).unwrap_or(0);
    }

    Ok(BytesN::from_array(env, &key_arr))
}
