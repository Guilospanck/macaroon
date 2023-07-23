use serde::{Deserialize, Serialize};

use crate::macaroon::Macaroon;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Eq)]
pub enum CaveatType {
  FirstParty,
  ThirdParty,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caveat {
  /// Location of the service that will discharge it.
  pub location: Option<String>,
  /// If caveat is 1st party, it is the predicate. Otherwise,
  /// it is the identifier of the discharge macaroon.
  pub identifier_or_predicate: String,
  /// Encrypts the caveat root key (`cK` -
  /// the root key used to create the macaroon that will discharge this 3rd party caveat)
  /// with the signature of the authorising (original - `TM`) macaroon as the encryption key.
  ///
  /// `vid = ENC(TM.sig, cK)`, where ENC is a symmetric cryptography function
  pub verification_key_identifier: String,
  /// Either 1st or 3rd party.
  pub(crate) _type: CaveatType,
}

impl Caveat {
  pub(crate) fn first_party(&self) -> bool {
    self._type == CaveatType::FirstParty
  }

  pub(crate) fn third_party(&self) -> bool {
    self._type == CaveatType::ThirdParty
  }

  /// Returns an updated signature in face of new caveats added.
  ///
  pub fn get_updated_signature(&self, prev_signature: &str) -> String {
    let first = Macaroon::get_new_signature(prev_signature, &self.verification_key_identifier);
    let second = Macaroon::get_new_signature(prev_signature, &self.identifier_or_predicate);
    let concatenated = format!("{}{}", first, second);
    Macaroon::get_new_signature(prev_signature, &concatenated)
  }
}

#[cfg(test)]
mod tests {

  use super::*;

  #[cfg(test)]
  use pretty_assertions::assert_eq;

  #[test]
  fn should_encrypt_and_decrypt_data_correctly_with_random_generated_key() {
    let previous_signature = "ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1";
    let caveat_first_party = Caveat {
      _type: CaveatType::FirstParty,
      location: None,
      identifier_or_predicate: "potato = yes".to_string(),
      verification_key_identifier: "0".to_string()
    };
    assert!(caveat_first_party.first_party());

    let caveat_third_party = Caveat {
      _type: CaveatType::FirstParty,
      location: Some("potato.com".to_string()),
      identifier_or_predicate: "caveat_identifier".to_string(),
      verification_key_identifier: "c2decd2bc849a6764312167c7c12b9aa3e07d5c733581ffd17f499d4ec8d23e5".to_string()
    };
    assert!(caveat_third_party.first_party());

    let expected_signature_first_party = "0ea4d26c44dedac2e8d96ae05a199e4453e76fb3f7ea47924b98e841aa0a42f3".to_string();
    let expected_signature_third_party = "ed9285c19040651ed738cbe36ac1717a2143d68b7f4ba2655d6b133210e98ff3".to_string();
    
    let updated_signature_first_party = caveat_first_party.get_updated_signature(previous_signature);
    let updated_signature_third_party = caveat_third_party.get_updated_signature(previous_signature);

    assert_eq!(updated_signature_first_party, expected_signature_first_party);
    assert_eq!(updated_signature_third_party, expected_signature_third_party);

  }
}
