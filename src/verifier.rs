use std::{collections::BTreeSet, vec};

use crate::{crypto::Crypto, macaroon::Macaroon};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum VerifyError {
  #[error("Error: Predicates not satisfied!")]
  PredicatesNotSatisfied,
  #[error("Error: Discharge macaroon not verified!")]
  DischargeMacaroonNotVerified,
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

  /// Adds a new exact `predicate` to the list of predicates
  /// to be verified when the `verify` function is called.
  ///
  pub fn satisfy_exact(&mut self, predicate: &str) -> &mut Self {
    // if predicate already exists, it won't add a new one.
    self.predicates.insert(predicate.to_string());
    self
  }

  /// Adds a new general `predicate` (which is a function) to the list of callbacks
  /// to be called in order to verify a predicate when
  /// the `verify` function is called.
  ///
  pub fn satisfy_general(&mut self, func: CallbackFnVerify) {
    self.callbacks.push(func);
  }

  /// Verifies exact predicates that are in the list.
  ///
  fn verify_exact(&self, predicate: &str) -> bool {
    self.predicates.contains(&predicate.to_string())
  }

  /// Verifies general predicates that are in the list.
  ///
  fn verify_general(&self, predicate: &str) -> bool {
    for callback in self.callbacks.iter() {
      if callback(predicate.to_string()) {
        return true;
      }
    }
    false
  }

  /// Verifies if all predicates are satisfied in a macaroon, including
  /// the 1st and 3rd party caveats and discharge macaroons.
  /// Returns `Ok(())` if all of them are succesfully verified and
  /// and `Err(VerifyError)` if not.
  ///
  pub fn verify(
    &self,
    macaroon: Macaroon,
    root_key: &str,
    discharge_macaroons: Vec<Macaroon>,
    parent_signature: Option<&str>,
  ) -> Result<(), VerifyError> {
    let mut current_signature = Macaroon::get_new_signature(root_key, &macaroon.identifier);

    for caveat in macaroon.caveat_list {
      let vid = caveat.clone().verification_key_identifier;
      let caveat_id = caveat.clone().identifier_or_predicate;

      if caveat.first_party() {
        current_signature = caveat.get_updated_signature(&current_signature);
        if self.predicates.is_empty() && self.callbacks.is_empty() {
          continue;
        }

        if !(self.verify_exact(&caveat_id) || self.verify_general(&caveat_id)) {
          return Err(VerifyError::PredicatesNotSatisfied);
        }
      }

      if caveat.third_party() {
        // Extracts the caveat root key (cK) from vID
        let caveat_root_key = Crypto::decrypt(&current_signature, &vid);
        current_signature = caveat.get_updated_signature(&current_signature);

        // - Check if there is a discharge macaroon (M') in the vec of
        // discharged macaroons (_M) that:
        //    a) its cID is the same as caveat_id;
        //    b) can be recursively verified by invoking M'.verify(TM, cK, _M)
        //    c) Checks that the signature of the current macaroon (M') is a proper
        //       chained MAC signature *bound* to the authorisation macaroon (TM).

        // a)
        let discharge_macaroon_contain_caveat_id = discharge_macaroons
          .iter()
          .find(|discharge_mac| discharge_mac.identifier == caveat_id);

        match discharge_macaroon_contain_caveat_id {
          Some(discharge_macaroon) => {
            // b)
            let result = self.verify(
              discharge_macaroon.clone(),
              &caveat_root_key,
              discharge_macaroons.clone(),
              Some(current_signature.clone().as_str()),
            );
            if result.is_err() {
              return Err(VerifyError::DischargeMacaroonNotVerified);
            }

            // get original signature of discharge macaroon without being bound to authorisation macaroon
            let mut discharge_mac_original_sig =
              Macaroon::get_new_signature(&caveat_root_key, &discharge_macaroon.identifier);
            for discharge_mac_caveat in discharge_macaroon.caveat_list.iter() {
              discharge_mac_original_sig =
                discharge_mac_caveat.get_updated_signature(&discharge_mac_original_sig);
            }

            // get bound discharge macaroon signature
            let bound_discharge_macaroon_signature =
              Macaroon::get_bound_signature(discharge_mac_original_sig, current_signature.clone());
            // c)
            if bound_discharge_macaroon_signature != discharge_macaroon.signature {
              return Err(VerifyError::SignaturesDoNotMatch);
            }
          }
          None => return Err(VerifyError::DischargeMacaroonNotVerified),
        }
      }
    }

    if macaroon.signature != current_signature
      && macaroon.signature
        != Macaroon::get_bound_signature(
          current_signature,
          parent_signature.unwrap_or("").to_string(),
        )
    {
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
  fn verify_ok_when_no_conditions_to_verify() {
    let root_key = "potato";
    let identifier = "test-id";
    let location = Some("https://some.location");
    let authorisation_predicate = "potato = larry";
    let another_authorisation_predicate = "another = one";

    let mut macaroon = Macaroon::create(root_key, identifier, location);
    macaroon.add_first_party_caveat(authorisation_predicate);
    macaroon.add_first_party_caveat(another_authorisation_predicate);

    let verifier = Verifier::new();
    let result = verifier.verify(macaroon, root_key, vec![], None);

    assert!(result.is_ok());
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
    let result = verifier.verify(macaroon, root_key, vec![], None);

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

    let result = verifier.verify(macaroon, root_key, vec![], None);

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
    let result = verifier.verify(macaroon, root_key, vec![], None);

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
    let result = verifier.verify(macaroon, "another_root_key", vec![], None);

    assert!(result.is_err());
    assert_eq!(result.err().unwrap(), VerifyError::SignaturesDoNotMatch);
  }

  #[test]
  fn verify_third_party_caveat_with_discharge_macaroons() {
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
    bound_macaroon.signature =
      original_macaroon.bind_for_request(discharge_macaroon.signature.clone());

    let expected_bound_signature = Macaroon::get_bound_signature(
      discharge_macaroon.clone().signature,
      original_macaroon.clone().signature,
    );

    assert_eq!(bound_macaroon.signature, expected_bound_signature);

    let mut verifier = Verifier::default();
    // must satisfy first caveat from the original macaroon
    verifier.satisfy_exact(predicate_account_id);
    // must satisfy the first caveat from the discharge macaroon
    verifier.satisfy_exact(first_party_caveat_of_discharge_macaroon_identifier);

    // get verified result from discharge macaroon that DOES NOT have the signature bound to the authorisation macaroon
    let discharge_macaroon_with_signature_not_bound_to_authorisation_macaroon_verifier = verifier
      .verify(
        original_macaroon.clone(),
        root_key,
        vec![discharge_macaroon],
        None,
      );

    assert!(
      discharge_macaroon_with_signature_not_bound_to_authorisation_macaroon_verifier.is_err()
    );
    assert_eq!(
      discharge_macaroon_with_signature_not_bound_to_authorisation_macaroon_verifier
        .err()
        .unwrap(),
      VerifyError::SignaturesDoNotMatch
    );

    // get verified result from discharge macaroon that DOES have the signature bound to the authorisation macaroon
    let discharge_macaroon_with_signature_bound_to_authorisation_macaroon_verifier =
      verifier.verify(original_macaroon, root_key, vec![bound_macaroon], None);

    assert!(discharge_macaroon_with_signature_bound_to_authorisation_macaroon_verifier.is_ok());
  }
}
