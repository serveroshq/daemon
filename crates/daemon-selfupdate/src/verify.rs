//! Checksum and signature. The public key is baked in at build time
//! (`SERVEROS_RELEASE_PUBKEY`, hex); a build without one cannot update
//! itself, which is the safe failure.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::UpdateError;

pub fn release_key() -> Option<VerifyingKey> {
    let hex_key = option_env!("SERVEROS_RELEASE_PUBKEY")?;
    let bytes: [u8; 32] = hex::decode(hex_key).ok()?.try_into().ok()?;

    VerifyingKey::from_bytes(&bytes).ok()
}

pub fn verify_with(
    key: &VerifyingKey,
    binary: &[u8],
    expected_sha256: &str,
    signature_b64: &str,
) -> Result<(), UpdateError> {
    let digest = hex::encode(Sha256::digest(binary));

    if !digest.eq_ignore_ascii_case(expected_sha256.trim()) {
        return Err(UpdateError::ChecksumMismatch);
    }

    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| UpdateError::BadSignature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| UpdateError::BadSignature)?;

    key.verify(binary, &signature)
        .map_err(|_| UpdateError::BadSignature)
}

pub fn verify(
    binary: &[u8],
    expected_sha256: &str,
    signature_b64: &str,
) -> Result<(), UpdateError> {
    let key = release_key().ok_or(UpdateError::NoReleaseKey)?;

    verify_with(&key, binary, expected_sha256, signature_b64)
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn accepts_a_valid_signature_and_rejects_tampering() {
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        let key = signing.verifying_key();
        let binary = b"pretend this is serverosd";
        let sha = hex::encode(Sha256::digest(binary));
        let sig = base64::engine::general_purpose::STANDARD.encode(signing.sign(binary).to_bytes());

        assert!(verify_with(&key, binary, &sha, &sig).is_ok());
        assert!(matches!(
            verify_with(&key, b"tampered", &sha, &sig),
            Err(UpdateError::ChecksumMismatch)
        ));

        let tampered_sha = hex::encode(Sha256::digest(b"tampered"));
        assert!(matches!(
            verify_with(&key, b"tampered", &tampered_sha, &sig),
            Err(UpdateError::BadSignature)
        ));

        let other = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        assert!(matches!(
            verify_with(&other, binary, &sha, &sig),
            Err(UpdateError::BadSignature)
        ));
    }
}
