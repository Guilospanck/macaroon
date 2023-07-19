use crate::macaroon::Macaroon;

#[derive(Debug, Clone, PartialEq)]
pub enum CaveatType {
  FirstParty,
  ThirdParty,
}

#[derive(Debug, Clone)]
pub struct Caveat {
  /// Location of the service that will discharge it.
  pub location: Option<String>,
  /// If caveat is 1st party, it is the predicate. Otherwise, 
  /// it is the identifier of the discharge macaroon.
  pub identifier: String,
  /// Encrypts the caveat root key (`cK` -
  /// the root key used to create the macaroon that will discharge this 3rd party caveat)
  /// with the signature of the authorising (original - `TM`) macaroon as the encryption key.
  /// 
  /// `vid = ENC(TM.sig, cK)`
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

  pub fn update_signature(&self, prev_signature: &str) -> String {
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