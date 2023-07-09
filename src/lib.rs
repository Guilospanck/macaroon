//! The macaroon crate implements macaroons as described in
//! the paper "Macaroons: Cookies with Contextual Caveats for
//! Decentralized Authorization in the Cloud"
//! (http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)
//!

#![allow(dead_code)]

mod caveat;
pub mod verifier;
pub mod macaroon;
