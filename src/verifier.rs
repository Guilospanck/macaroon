use std::{collections::BTreeSet, vec};

use crate::{macaroon::Macaroon};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerifyError {
  #[error("Error: Predicates not satisfied!")]
  PredicatesNotSatisfied,
  #[error("Error: Signatures don't match")]
  SignaturesDoNotMatch,
}

pub type CallbackFnVerify = fn(String) -> bool;

pub struct Verifier {
  predicates: BTreeSet<String>,
  callbacks: Vec<CallbackFnVerify>,
}

impl Default for Verifier {
  fn default() -> Self {
    Self::new()
  }
}

impl Verifier {
  pub fn new() -> Verifier {
    Verifier {
      predicates: BTreeSet::new(),
      callbacks: vec![],
    }
  }

  pub fn satisfy_exact(&mut self, predicate: &str) -> &mut Self {
    // if predicate already exists, it won't add a new one.
    self.predicates.insert(predicate.to_string());
    self
  }

  pub fn satisfy_general(&mut self, func: CallbackFnVerify) {
    self.callbacks.push(func);
  }

  fn verify_exact(&self, predicate: &str) -> bool {
    self.predicates.contains(&predicate.to_string())
  }

  fn verify_general(&self, predicate: &str) -> bool {
    for callback in self.callbacks.iter() {
      if callback(predicate.to_string()) {
        return true;
      }
    }
    false
  }

  pub fn verify(&self, macaroon: Macaroon, root_key: &str) -> Result<(), VerifyError> {
    let mut current_signature = Macaroon::get_new_signature(root_key, &macaroon.identifier);
    for caveat in macaroon.caveat_list {
      if caveat.first_party() {
        if !(self.verify_exact(&caveat.identifier) || self.verify_general(&caveat.identifier)) {
          return Err(VerifyError::PredicatesNotSatisfied);
        }
        current_signature = caveat.update_signature(&current_signature);
      }
    }

    if macaroon.signature != current_signature {
      return Err(VerifyError::SignaturesDoNotMatch);
    }

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(test)]
  use pretty_assertions::assert_eq;

  fn general_predicate_fn(predicate: String) -> bool {
    if !predicate.starts_with("another") {
      return false;
    }
    let split = predicate.split(" = ").next();
    match split {
      Some(remainder) => {
        if remainder != "another" {
          return false;
        }
        true
      }
      None => false,
    }
  }

  #[test]
  fn verify_ok_when_caveats_and_satisfy_conditions_match() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";
    let another_authorisation_predicate = "another = one";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);
    macaroon.add_first_party_caveat(another_authorisation_predicate);

    let mut verifier = Verifier::new();
    verifier.satisfy_exact(authorisation_predicate);
    verifier.satisfy_general(general_predicate_fn);
    let result = verifier.verify(macaroon, root_key);

    assert!(result.is_ok());
  }

  #[test]
  fn verify_ok_when_all_caveats_are_satisfied_by_at_least_one_condition() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);

    let mut verifier = Verifier::new();
    verifier.satisfy_exact(authorisation_predicate);
    verifier.satisfy_general(general_predicate_fn);

    let result = verifier.verify(macaroon, root_key);

    // Even though we have one caveat and two satisfy conditions,
    // if the caveat is satisfied in one of them, we are good to go.
    assert!(result.is_ok());
  }

  #[test]
  fn verify_throw_err_when_predicates_dont_match() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);

    let mut verifier = Verifier::new();
    verifier.satisfy_exact("another = thing");
    let result = verifier.verify(macaroon, root_key);

    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), VerifyError::PredicatesNotSatisfied);
  }

  #[test]
  fn verify_throw_err_when_signatures_dont_match() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);

    let mut verifier = Verifier::new();
    verifier.satisfy_exact(authorisation_predicate);
    let result = verifier.verify(macaroon, "another_root_key");

    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), VerifyError::SignaturesDoNotMatch);
  }
}
