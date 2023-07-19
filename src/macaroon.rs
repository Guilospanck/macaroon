use crate::{
  caveat::{Caveat, CaveatType},
  crypto::Crypto,
};

use sha2::{Digest, Sha256};

#[derive(Clone)]
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

  /// Adds third party caveat to the Macaroon and returns a
  /// mutable reference (fluent interface).
  ///
  /// A third party caveat is a caveat which must be verified by
  /// a third party using macaroons that are provided by them.
  /// They are known as "discharge macaroons".
  ///
  pub fn add_third_party_caveat(
    &mut self,
    caveat_root_key: &str,
    identifier: &str,
    location: Option<&str>,
  ) -> &mut Self {
    // vID (verification key identifier): Encrypts the key cK (caveat root key) with the signature of the macaroon as the encryption key;
    let vid = Crypto::encrypt(&self.signature, caveat_root_key);
    self.add_caveat_helper(Caveat {
      location: location.map(|loc| loc.to_string()),
      identifier: identifier.to_string(),
      verification_key_identifier: vid,
      _type: CaveatType::ThirdParty,
    })
  }

  /// Binds the discharging to the authorising macaroon.
  ///
  /// `M'.sig = sha256(M'.sig || TM.sig)`
  ///
  fn bind_for_request(&self, discharge_macaroon: &mut Macaroon) {
    discharge_macaroon.signature =
      Macaroon::get_bound_signature(discharge_macaroon.signature.clone(), self.signature.clone());
  }

  pub(crate) fn get_bound_signature(
    discharge_macaroon_signature: String,
    authorising_macaroon_signature: String,
  ) -> String {
    let concatenated = format!(
      "{}{}",
      discharge_macaroon_signature, authorising_macaroon_signature
    );
    Macaroon::hash_with_sha256(&concatenated)
  }

  pub fn serialize(&self) -> String {
    "".to_string()
  }

  /// Helper to HMAC-hash an identifier using a secret.
  ///
  pub(crate) fn get_new_signature(secret: &str, identifier: &str) -> String {
    Crypto::hmac_sha256(secret, identifier)
  }

  fn hash_with_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
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
  fn add_third_party_caveat() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://macaroon.location");
    let mut original_macaroon = Macaroon::create(root_key, identifier, location);
    let original_macaroon_signature = original_macaroon.signature.clone();

    let caveat_discharge_location = Some("https://auth.bank");
    let caveat_identifier = "caveat-identifier";
    let caveat_root_key = "caveat-root-key";

    original_macaroon.add_third_party_caveat(
      caveat_root_key,
      caveat_identifier,
      caveat_discharge_location,
    );

    let macaroon_first_caveat = original_macaroon.caveat_list.first().unwrap();
    let expected_caveat_root_key = Crypto::decrypt(
      &original_macaroon_signature,
      &macaroon_first_caveat.verification_key_identifier,
    );

    assert_eq!(original_macaroon.caveat_list.len(), 1);
    assert_eq!(
      macaroon_first_caveat.identifier,
      caveat_identifier.to_string()
    );
    assert!(macaroon_first_caveat.location.is_some());
    assert_eq!(
      macaroon_first_caveat.location,
      caveat_discharge_location.map(|loc| loc.to_string())
    );
    assert_eq!(expected_caveat_root_key, caveat_root_key.to_string());
  }

  #[test]
  fn bind_for_request() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://macaroon.location");
    let mut original_macaroon = Macaroon::create(root_key, identifier, location);
    let predicate_account_id = "account_id = 007";
    original_macaroon.add_first_party_caveat(predicate_account_id);

    // Adds 3rd party caveat to the original macaroon
    let caveat_discharge_location = Some("https://auth.bank");
    let caveat_identifier = "caveat-identifier";
    let caveat_root_key = "caveat-root-key";

    original_macaroon.add_third_party_caveat(
      caveat_root_key,
      caveat_identifier,
      caveat_discharge_location,
    );

    // Creates the discharge macaroon that will be responsible for
    // handling the 3rd party caveat just created.
    let mut discharge_macaroon = Macaroon::create(
      caveat_root_key,
      caveat_identifier,
      caveat_discharge_location,
    );
    let first_party_caveat_of_discharge_macaroon_identifier = "time < 2023-07-09T00:00:00Z";
    discharge_macaroon.add_first_party_caveat(first_party_caveat_of_discharge_macaroon_identifier);

    // Bind the discharge to the original macaroon
    let mut bound_macaroon = discharge_macaroon.clone();
    original_macaroon.bind_for_request(&mut bound_macaroon);

    let expected_bound_signature =
      Macaroon::get_bound_signature(discharge_macaroon.signature, original_macaroon.signature);

    assert_eq!(bound_macaroon.signature, expected_bound_signature);

    // For integration test
    // Verifies
    // let mut verifier = Verifier::default();
    // // must satisfy first caveat from the original macaroon
    // verifier.satisfy_exact(predicate_account_id);
    // // must satisfy the first caveat from the discharge macaroon
    // verifier.satisfy_exact(first_party_caveat_of_discharge_macaroon_identifier);
    // assert!(verifier.verify(macaroon, root_key, vec![discharge_macaroon]).is_err());
    // assert!(verifier.verify(macaroon, root_key, vec![bound_macaroon]).is_ok());
  }

  #[test]
  fn get_new_signature() {
    let root_key = "potato";
    let identifier = "test-id";
    let expected_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";

    let signature = Macaroon::get_new_signature(root_key, identifier);
    assert_eq!(signature, expected_signature.to_string());
  }
}
