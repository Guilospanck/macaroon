use crypto_secretbox::{
  aead::{Aead, AeadCore, KeyInit, OsRng},
  Key, Nonce, XSalsa20Poly1305,
};
use hex;

pub struct Crypto {}

impl Crypto {
  /// Generates random symmetric key that
  /// can be used as root key for macaroons.
  ///
  pub fn get_random_key() -> String {
    let key = XSalsa20Poly1305::generate_key(&mut OsRng);
    format!("{:x}", key)
  }

  // TODO: we need a symmetric cryptography in order to use the same secret to enc and dec.
  // TODO: find a way of using a random key as the secret here in the cypher
  /// Encrypts data
  ///
  pub fn encrypt(key: &str, data: &str) -> String {
    let key_bytes: &[u8] = key.as_bytes();
    let cipher = XSalsa20Poly1305::new_from_slice(key_bytes).unwrap();
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data.as_bytes().as_ref()).unwrap();

    // Adds nonce to the beginning of the data so
    // we can retrieve it after with NONCE_SIZE (TODO: to check)
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(nonce);
    ret.extend(ciphertext);

    hex::encode(ret)
  }
}
