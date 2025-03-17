use anyhow::Result;
use argon2::{
    Algorithm, Argon2, Params, Version,
};
use rand::{rngs::OsRng, RngCore};
use ring::aead::{self, UnboundKey, Aad, NONCE_LEN, Nonce, LessSafeKey};
use zeroize::Zeroize;

use crate::utils::constants::{KEY_LEN, MEMORY_COST, PARALLELISM, SALT_SIZE, TAG_SIZE, TIME_COST};
use crate::utils::errors::AppError;

#[derive(Debug)]
pub struct MasterKey {
    key: [u8; KEY_LEN],
}

impl MasterKey {
    pub fn new(password: &str, salt: &[u8]) -> Result<Self> {
        let mut key = [0u8; KEY_LEN];
        
        let params = Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(KEY_LEN))
            .map_err(|e| AppError::EncryptionError(e.to_string()))?;
            
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| AppError::EncryptionError(e.to_string()))?;
        
        Ok(Self { key })
    }
    
    pub fn get_key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub struct Crypto;

impl Crypto {
    pub fn generate_salt() -> [u8; SALT_SIZE] {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        salt
    }
    
    pub fn encrypt(plaintext: &[u8], master_key: &MasterKey) -> Result<Vec<u8>> {
        // Create a new nonce for each encryption
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        // Create the key
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, master_key.get_key())
            .map_err(|_| AppError::EncryptionError("Failed to create encryption key".to_string()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        // Encrypt the plaintext
        let mut in_out = plaintext.to_vec();
        let tag = less_safe_key.seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| AppError::EncryptionError("Encryption failed".to_string()))?;
        
        // Assemble final ciphertext: nonce + encrypted data + tag
        let mut result = Vec::with_capacity(NONCE_LEN + in_out.len() + tag.as_ref().len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&in_out);
        result.extend_from_slice(tag.as_ref());
        
        Ok(result)
    }
    
    pub fn decrypt(ciphertext: &[u8], master_key: &MasterKey) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_LEN + TAG_SIZE {
            return Err(AppError::DecryptionError("Invalid ciphertext length".to_string()).into());
        }
        
        // Extract nonce
        let nonce_bytes = &ciphertext[..NONCE_LEN];
        let nonce_array = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| AppError::DecryptionError("Invalid nonce".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_array);
        
        // The remaining bytes include both the encrypted data and the tag
        let mut in_out = ciphertext[NONCE_LEN..].to_vec();
        
        // Create decryption key
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, master_key.get_key())
            .map_err(|_| AppError::DecryptionError("Failed to create decryption key".to_string()))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        
        // Decrypt in place. The returned slice is the plaintext.
        let decrypted_data = less_safe_key.open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| AppError::DecryptionError("Decryption failed: authentication failed".to_string()))?;
        
        Ok(decrypted_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let password = "test_password";
        let salt = Crypto::generate_salt();
        let master_key = MasterKey::new(password, &salt).unwrap();
        
        let plaintext = b"This is a secret message";
        let encrypted = Crypto::encrypt(plaintext, &master_key).unwrap();
        let decrypted = Crypto::decrypt(&encrypted, &master_key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_different_keys() {
        let password1 = "password1";
        let password2 = "password2";
        let salt = Crypto::generate_salt();
        
        let master_key1 = MasterKey::new(password1, &salt).unwrap();
        let master_key2 = MasterKey::new(password2, &salt).unwrap();
        
        let plaintext = b"Secret data";
        let encrypted = Crypto::encrypt(plaintext, &master_key1).unwrap();
        
        // Decryption with wrong key should fail
        let result = Crypto::decrypt(&encrypted, &master_key2);
        assert!(result.is_err());
    }
} 