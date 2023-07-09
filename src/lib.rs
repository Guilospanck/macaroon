//! The macaroon crate implements macaroons as described in
//! the paper "Macaroons: Cookies with Contextual Caveats for
//! Decentralized Authorization in the Cloud"
//! (http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)
//!

#![allow(dead_code)]

use std::vec;

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

#[derive(Debug, Clone, PartialEq)]
enum CaveatType {
  FirstParty,
  ThirdParty,
}

pub struct Verifier {
  predicates: Vec<String>,
  callbacks: Vec<fn()>,
}

impl Verifier {
  pub fn new() -> Verifier {
    Verifier {
      predicates: vec![],
      callbacks: vec![],
    }
  }

  pub fn satisfy_exact(&mut self, predicate: &str) -> &mut Self {
    self.predicates.push(predicate.to_string());
    self
  }

  pub fn satisfy_general(&mut self, func: fn()) {
    self.callbacks.push(func);
  }

  fn verify_exact(&self, predicate: &str) -> bool {
    self.predicates.contains(&predicate.to_string())
  }

  pub fn verify(&self, _macaroon: Macaroon) -> bool {
    true
  }
}

#[derive(Debug, Clone)]
pub struct Caveat {
  pub location: Option<String>,
  pub identifier: String,
  pub verification_key_identifier: String,
  _type: CaveatType,
}

impl Caveat {
  fn first_party(&self) -> bool {
    self._type == CaveatType::FirstParty
  }

  fn third_party(&self) -> bool {
    self._type == CaveatType::ThirdParty
  }

  pub fn get_signature(&self, prev_signature: &str) -> String {
    if self.first_party() {
      return Macaroon::get_new_signature(prev_signature, &self.identifier);
    }

    if self.third_party() {
      let first = Macaroon::get_new_signature(prev_signature, &self.verification_key_identifier);
      let second = Macaroon::get_new_signature(prev_signature, &self.identifier);
      let concatenated = format!("{}{}", first, second);
      return Macaroon::get_new_signature(prev_signature, &concatenated);
    }

    panic!("Expected a caveat of first or third party")
  }
}

pub struct Macaroon {
  pub identifier: String,
  pub caveat_list: Vec<Caveat>,
  pub location: Option<String>,
  pub signature: String,
}

impl Macaroon {
  /// Creates a new Macaroon given:
  /// - a high-entropy root key;
  /// - an identifier id;
  /// - an optional location
  ///
  /// Returns a Macaroon with these data plus
  /// a valid signature (sig = `HMAC(root_key, identifier)`) and an
  /// empty list of caveats.
  ///
  pub fn create(root_key: &str, identifier: &str, location: Option<&str>) -> Self {
    let location: Option<String> = location.map(|loc| loc.to_string());

    let signature = Self::get_new_signature(root_key, identifier);

    Self {
      identifier: identifier.to_string(),
      caveat_list: vec![],
      location,
      signature,
    }
  }

  /// Adds caveat to the list of caveats in the Macaroon and
  /// generates the new signature accordingly to the type of
  /// caveat (First Party or Third Party).
  ///
  fn add_caveat_helper(&mut self, caveat: Caveat) -> &mut Self {
    self.caveat_list.push(caveat.clone());
    self.signature = caveat.get_signature(&self.signature);
    self
  }

  /// Adds first party caveat to the Macaroon and returns a
  /// mutable reference (fluent interface).
  ///
  pub fn add_first_party_caveat(&mut self, authorisation_predicate: &str) -> &mut Self {
    self.add_caveat_helper(Caveat {
      location: None,
      identifier: authorisation_predicate.to_string(),
      verification_key_identifier: "0".to_string(),
      _type: CaveatType::FirstParty,
    })
  }

  // verify
  // - calculate first signature from `root_key` and `identifier`
  // - for each caveat, check predicate and calculate new signature
  // - check signatures match
  pub fn verify(&self) -> bool {
    true
  }

  pub fn serialize(&self) -> String {
    "".to_string()
  }

  /// Helper to HMAC-hash an identifier using a secret.
  ///
  fn get_new_signature(secret: &str, identifier: &str) -> String {
    let mut mac =
      HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    let identifier = identifier.to_string();
    mac.update(identifier.as_bytes());
    let result = mac.finalize().into_bytes();
    format!("{:x}", result)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(test)]
  use pretty_assertions::assert_eq;

  #[test]
  fn create_macaroon() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = None;

    let macaroon = Macaroon::create(root_key, identifier, location);

    let expected_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";

    assert_eq!(macaroon.identifier, identifier.to_string());
    assert!(macaroon.location.is_none());
    assert_eq!(macaroon.signature, expected_signature.to_string());
    assert_eq!(macaroon.caveat_list.len(), 0);
  }

  #[test]
  fn add_first_party_caveat() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);

    assert_eq!(macaroon.caveat_list.len(), 1);
    assert_eq!(
      macaroon.caveat_list.first().unwrap().identifier,
      authorisation_predicate.to_string()
    );
    assert_eq!(
      macaroon
        .caveat_list
        .first()
        .unwrap()
        .verification_key_identifier,
      "0".to_string()
    );
    assert!(macaroon.caveat_list.first().unwrap().location.is_none());

    let expected_signature = "e2342be14bf8d8f1f3fc54abfe877a80e446c40437785747096a8233c7aeb8ab";

    assert_eq!(macaroon.signature, expected_signature.to_string());
  }

  #[test]
  fn verify() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);

    // verify
    // - calculate first signature from `root_key` and `identifier`
    // - for each caveat, check predicate and calculate new signature
    // - check signatures match
    let predicate_to_verify = "potato = larry";
    let first_signature = Macaroon::get_new_signature(root_key, identifier);
    for caveat in macaroon.caveat_list {
      if caveat.first_party() {
        // builds new signature
        let new_signature = Macaroon::get_new_signature(&first_signature, &caveat.identifier);
      }
    }

    assert!(true);
  }

  #[test]
  fn hmac_sha256() {
    let root_key = "potato";
    let identifier = "test-id";
    let expected_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";

    let signature = Macaroon::get_new_signature(root_key, identifier);
    assert_eq!(signature, expected_signature.to_string());
  }
}
