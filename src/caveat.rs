use crate::macaroon::Macaroon;

#[derive(Debug, Clone, PartialEq)]
pub enum CaveatType {
  FirstParty,
  ThirdParty,
}

#[derive(Debug, Clone)]
pub struct Caveat {
  pub location: Option<String>,
  pub identifier: String,
  pub verification_key_identifier: String,
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