use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct AsymmetricKeys {
  pub private_key: SecretKey,
  pub public_key: PublicKey,
}

///
/// Generates random keypairs (private and public keys) that
/// can be used as root key for macaroons.
///
pub fn generate_keys() -> AsymmetricKeys {
  let secp = Secp256k1::new();
  let mut rng = rand::thread_rng();

  let (seckey, pubkey) = secp.generate_keypair(&mut rng);
  assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));

  AsymmetricKeys {
    public_key: pubkey,
    private_key: seckey,
  }
}
