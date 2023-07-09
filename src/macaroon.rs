use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::caveat::{Caveat, CaveatType};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

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
    self.signature = caveat.update_signature(&self.signature);
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

  pub fn serialize(&self) -> String {
    "".to_string()
  }

  /// Helper to HMAC-hash an identifier using a secret.
  ///
  pub(crate) fn get_new_signature(secret: &str, identifier: &str) -> String {
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
  fn hmac_sha256() {
    let root_key = "potato";
    let identifier = "test-id";
    let expected_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";

    let signature = Macaroon::get_new_signature(root_key, identifier);
    assert_eq!(signature, expected_signature.to_string());
  }
}
