use hmac::Hmac;
use sha2::Sha256;
use std::str;

use crypto_secretbox::{
  aead::{Aead, AeadCore, KeyInit, OsRng},
  XSalsa20Poly1305,
};
use hex;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

pub struct Crypto {}

impl Crypto {
  /// Generates random symmetric key that
  /// can be used as root key for macaroons.
  ///
  pub fn get_random_key() -> String {
    let key = XSalsa20Poly1305::generate_key(&mut OsRng);
    hex::encode(key)
  }

  /// Encrypts data using `XSalsa20Poly1305` (symmetric cryptography).
  ///
  pub fn encrypt(key: &str, data: &str) -> String {
    let key_bytes = hex::decode(key).unwrap();
    let cipher = XSalsa20Poly1305::new_from_slice(&key_bytes).unwrap();
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data.as_bytes().as_ref()).unwrap();

    // Adds nonce to the beginning of the data so
    // we can retrieve it after with NONCE_SIZE (TODO: to check)
    let mut ret: Vec<u8> = Vec::new();
    ret.extend(nonce);
    ret.extend(ciphertext);

    hex::encode(ret)
  }

  /// Decrypts data that were encrypted using `XSalsa20Poly1305` (symmetric cryptography).
  ///
  pub fn decrypt(key: &str, data: &str) -> String {
    // get info from the data
    let nonce_size = XSalsa20Poly1305::NONCE_SIZE;
    let data_bytes = hex::decode(data).unwrap();
    let nonce = &data_bytes[..nonce_size];
    let ciphertext = &data_bytes[nonce_size..];

    // get cipher from key
    let key_bytes = hex::decode(key).unwrap();
    let cipher = XSalsa20Poly1305::new_from_slice(&key_bytes).unwrap();

    // decript
    let decripted = cipher.decrypt(nonce.into(), ciphertext).unwrap();

    str::from_utf8(&decripted).unwrap().to_string()
  }

  /// Hashes `data` with HMAC-256 using the key `secret`.
  /// 
  pub fn hmac_sha256(secret: &str, data: &str) -> String {
    let mut mac =
    HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    let identifier = data.to_string();
    let result;
    {
      use hmac::Mac;
      mac.update(identifier.as_bytes());
      result = mac.finalize().into_bytes();
    }
    hex::encode(result)
  }
}

#[cfg(test)]
mod tests {

  use super::*;

  #[cfg(test)]
  use pretty_assertions::assert_eq;

  #[test]
  fn should_encrypt_and_decrypt_data_correctly_with_random_generated_key() {
    let key = Crypto::get_random_key();
    let data = "this is the message that I am going to encrypt and decrypt";

    let encrypted = Crypto::encrypt(&key, data);
    let decrypted = Crypto::decrypt(&key, &encrypted);

    assert_eq!(data.to_string(), decrypted);
  }

  #[test]
  fn should_encrypt_and_decrypt_data_correctly_with_some_key() {
    let key = String::from("ca454e90d6598ee2a0ae871ddf58c8b61543c2efbd2e8e58e216095c7cda3ee1");
    let data = "this is the message that I am going to encrypt and decrypt";

    let encrypted = Crypto::encrypt(&key, data);
    let encrypted2 = Crypto::encrypt(&key, data);
    // asserts that even though the key and the data are the same,
    // the encryption generated will be different due to nonce
    assert_ne!(encrypted, encrypted2);
    let decrypted = Crypto::decrypt(&key, &encrypted);

    assert_eq!(data.to_string(), decrypted);
  }
}
