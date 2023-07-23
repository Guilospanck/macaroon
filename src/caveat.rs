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
