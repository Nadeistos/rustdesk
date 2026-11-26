//! Unattended access for the technician of a custom build.
//!
//! The client edition is built with the technician's Ed25519 public key (`TECH_PUBLIC_KEY`).
//! A technician PC holds the matching 32-byte seed, base64-encoded, in `technicien.key`
//! in the config directory. Instead of a password hash, it sends a signature of the
//! connection's salt and challenge, which the client accepts without a password or a click.
//! The private key never ends up in a binary, so leaked executables grant no access.

use base::message_proto::Hash;
use hbb_common::{config::Config, log, sodiumoxide::crypto::sign};

const KEY_FILE: &str = "technicien.key";
const CONTEXT: &[u8] = b"les-solutions-technicien-v1\0";

fn signed_message(hash: &Hash) -> Vec<u8> {
    let mut msg = CONTEXT.to_vec();
    msg.extend_from_slice(hash.salt.as_bytes());
    msg.push(0);
    msg.extend_from_slice(hash.challenge.as_bytes());
    msg
}

/// Login "password" for this connection, if this PC holds a technician key.
pub fn login_signature(hash: &Hash) -> Option<Vec<u8>> {
    let path = Config::path(KEY_FILE);
    let content = std::fs::read_to_string(&path).ok()?;
    let seed = match crate::decode64(content.trim()) {
        Ok(seed) => seed,
        Err(e) => {
            log::error!("Invalid technician key in {:?}: {}", path, e);
            return None;
        }
    };
    let Some(seed) = sign::Seed::from_slice(&seed) else {
        log::error!("Invalid technician key length in {:?}", path);
        return None;
    };
    let (_, sk) = sign::keypair_from_seed(&seed);
    Some(sign::sign_detached(&signed_message(hash), &sk).to_bytes().to_vec())
}

/// Whether `password` is a valid technician signature for this connection.
pub fn verify_login_signature(password: &[u8], hash: &Hash) -> bool {
    let Some(pk) = option_env!("TECH_PUBLIC_KEY").filter(|s| !s.is_empty()) else {
        return false;
    };
    verify_with_key(pk, password, hash)
}

fn verify_with_key(pk_base64: &str, password: &[u8], hash: &Hash) -> bool {
    if password.len() != sign::SIGNATUREBYTES {
        return false;
    }
    let Some(pk) = crate::common::get_rs_pk(pk_base64) else {
        log::error!("Invalid TECH_PUBLIC_KEY");
        return false;
    };
    let Ok(sig) = sign::Signature::from_bytes(password) else {
        return false;
    };
    sign::verify_detached(&sig, &signed_message(hash), &pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(challenge: &str) -> Hash {
        Hash {
            salt: "salt".to_owned(),
            challenge: challenge.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn signature_only_valid_for_its_challenge_and_key() {
        let (pk, sk) = sign::gen_keypair();
        let pk = crate::encode64(pk.0);
        let sig = sign::sign_detached(&signed_message(&hash("abc123")), &sk)
            .to_bytes()
            .to_vec();
        assert!(verify_with_key(&pk, &sig, &hash("abc123")));
        assert!(!verify_with_key(&pk, &sig, &hash("abc124")));
        let (other, _) = sign::gen_keypair();
        assert!(!verify_with_key(&crate::encode64(other.0), &sig, &hash("abc123")));
        assert!(!verify_with_key(&pk, &sig[..32], &hash("abc123")));
    }
}
