use aes_gcm::aead::generic_array::typenum::U12;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{KeyInit, OsRng},
};

pub fn generate_cipher() -> Aes256Gcm {
    let key = Aes256Gcm::generate_key(OsRng);
    Aes256Gcm::new(&key)
}

pub fn generate_nonce() -> Nonce<U12> {
    let mut nonce_bytes = [0u8; 12]; // AES-GCM requires a 96-bit (12-byte) nonce
    OsRng.fill_bytes(&mut nonce_bytes); // Fill the nonce with random bytes
    *Nonce::from_slice(&nonce_bytes) // Convert the byte array into a Nonce
}
