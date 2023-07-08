#![allow(dead_code)]

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub struct AsymmetricKeys {
  pub private_key: SecretKey,
  pub public_key: PublicKey,
}

///
/// Generates random keypairs (private and public keys) that
/// can be used as root key for macaroons.
///
pub fn generate_keys() -> AsymmetricKeys {
  let secp = Secp256k1::new();
  let mut rng = rand::thread_rng();

  let (seckey, pubkey) = secp.generate_keypair(&mut rng);
  assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));

  AsymmetricKeys {
    public_key: pubkey,
    private_key: seckey,
  }
}
struct Macaroon {
  identifier: String,
  location: Option<String>,
  signature: String,
}

impl Macaroon {
  pub fn new(private_key: &str, identifier: &str, location: Option<&str>) -> Self {
    let location: Option<String> = match location {
      Some(loc) => Some(loc.to_string()),
      None => None,
    };

    let mut mac =
      HmacSha256::new_from_slice(private_key.as_bytes()).expect("HMAC can take key of any size");

    let identifier = identifier.to_string();
    mac.update(identifier.as_bytes());
    let signature = format!("{:x}", mac.finalize().into_bytes());

    Self {
      identifier,
      location,
      signature,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(test)]
  use pretty_assertions::assert_eq;

  #[test]
  fn create_macaroon() {
    let private_key = "potato";
    let identifier = "test-id";
    let location = None;

    let macaroon = Macaroon::new(private_key, identifier, location);

    let expected_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";

    assert_eq!(macaroon.identifier, identifier.to_string());
    assert!(macaroon.location.is_none());
    assert_eq!(macaroon.signature, expected_signature.to_string());
  }
}
