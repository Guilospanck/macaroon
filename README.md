# Macaroon [![codecov](https://codecov.io/gh/Guilospanck/macaroon/branch/main/graph/badge.svg?token=xVQ6o2ZpM6)](https://codecov.io/gh/Guilospanck/macaroon)

Simple implementation of macaroons as described in the paper ["Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"](http://theory.stanford.edu/~ataly/Papers/macaroons.pdf).

## How to use

- Creating a macaroon

```rs
use macaroon::{Macaroon, Verifier};

let root_key = "potato";
let identifier = "test-id";
let location = Some("https://macaroon.location");
let mut original_macaroon = Macaroon::create(root_key, identifier, location);
```

- Adding caveats

```rs
// Adds 1st party caveat to the original macaroon
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
```

- Create macaroon to discharge 3rd party caveat and bound it to the autorisation (original) macaroon

```rs
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
```

- Verify macaroons

```rs
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
```
