use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;
use std::io::{Read, Write};

use crate::encryption::crypto::{Crypto, MasterKey};
use crate::utils::constants::{DB_PATH, SALT_SIZE};
use crate::utils::errors::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    uuid: String,
    service: String,
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        service: String,
        username: String,
        password: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            uuid: Uuid::new_v4().to_string(),
            service,
            username,
            password,
            notes,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn update_password(&mut self, password: Option<String>) {
        self.password = password;
        self.updated_at = Utc::now();
    }
    
    pub fn update_notes(&mut self, notes: Option<String>) {
        self.notes = notes;
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    version: String,
    salt: [u8; SALT_SIZE],
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl VaultMetadata {
    pub fn new(salt: [u8; SALT_SIZE]) -> Self {
        let now = Utc::now();
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            salt,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    pub fn update_timestamp(&mut self) {
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Vault {
    metadata: VaultMetadata,
    credentials: HashMap<String, Vec<Credential>>,
}

impl Vault {
    fn new(salt: [u8; SALT_SIZE]) -> Self {
        Self {
            metadata: VaultMetadata::new(salt),
            credentials: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct CredentialManager {
    vault: Vault,
    master_key: MasterKey,
}

impl CredentialManager {
    pub fn initialize(master_password: &str, force: bool) -> Result<Self> {
        println!("DEBUG: Initializing vault at {:?}", *DB_PATH);
        
        if DB_PATH.exists() && !force {
            return Err(AppError::ConfigurationError(
                "Vault already exists. Use --force to reinitialize".to_string(),
            )
            .into());
        }

        // Generate a random salt
        let salt = Crypto::generate_salt();
        println!("DEBUG: Generated salt: {:?}", &salt[..5]); // Print first 5 bytes of salt for debugging
        
        // Create vault with the salt
        let vault = Vault::new(salt);
        
        // Serialize the vault to JSON
        let json = serde_json::to_vec(&vault)?;
        println!("DEBUG: Serialized vault, JSON size: {}", json.len());
        
        // Create master key from password and salt
        let master_key = MasterKey::new(master_password, &salt)?;
        println!("DEBUG: Created master key");
        
        // Ensure the parent directory exists
        if let Some(parent) = DB_PATH.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Write the salt first, then the encrypted data
        let mut file = fs::File::create(&*DB_PATH)?;
        file.write_all(&salt)?;
        
        // Encrypt using the master key
        let encrypted = Crypto::encrypt(&json, &master_key)?;
        file.write_all(&encrypted)?;
        
        println!("DEBUG: Vault initialized successfully");
        
        // Create the manager with the vault and master key
        let manager = Self { vault, master_key };
        println!("DEBUG: Created vault manager");

        Ok(manager)
    }

    pub fn load(master_password: &str) -> Result<Self> {
        if !DB_PATH.exists() {
            return Err(AppError::NotInitialized.into());
        }

        println!("DEBUG: Loading vault from {:?}", *DB_PATH);
        
        // Read the file
        let mut file = fs::File::open(&*DB_PATH)?;
        
        // Read the salt first (the first SALT_SIZE bytes)
        let mut salt = [0u8; SALT_SIZE];
        file.read_exact(&mut salt)?;
        
        println!("DEBUG: Read salt: {:?}", &salt[..5]); // Print first 5 bytes of salt for debugging
        
        // Create the master key with the salt from the file
        let master_key = MasterKey::new(master_password, &salt)?;
        
        // Read the rest of the file (the encrypted data)
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;
        
        println!("DEBUG: Read encrypted data, length: {}", encrypted.len());
        
        if encrypted.is_empty() {
            return Err(AppError::ConfigurationError("Vault file is empty".to_string()).into());
        }

        // Decrypt the data
        let decryption_result = Crypto::decrypt(&encrypted, &master_key);
        
        if let Err(ref e) = decryption_result {
            println!("DEBUG: Decryption error: {:?}", e);
        }
        
        let decrypted = decryption_result
            .map_err(|_| AppError::AuthenticationError("Invalid master password".to_string()))?;
            
        println!("DEBUG: Decryption successful, data length: {}", decrypted.len());
        
        // Parse the vault
        let vault_result = serde_json::from_slice(&decrypted);
        
        if let Err(ref e) = vault_result {
            println!("DEBUG: JSON parsing error: {:?}", e);
        }
        
        let vault: Vault = vault_result
            .map_err(|e| AppError::SerializationError(e))?;

        println!("DEBUG: Vault loaded successfully");
        
        Ok(Self { vault, master_key })
    }

    pub fn save(&self) -> Result<()> {
        println!("DEBUG: Saving vault to {:?}", *DB_PATH);
        
        let json = serde_json::to_vec(&self.vault)?;
        println!("DEBUG: Serialized vault, JSON size: {}", json.len());
        
        // Ensure the parent directory exists
        if let Some(parent) = DB_PATH.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut file = fs::File::create(&*DB_PATH)?;
        
        // First write the salt from the vault metadata
        let salt = self.vault.metadata.salt();
        println!("DEBUG: Writing salt: {:?}", &salt[..5]); // Print first 5 bytes of salt for debugging
        file.write_all(salt)?;
        
        // Then write the encrypted data
        let encrypted = Crypto::encrypt(&json, &self.master_key)?;
        println!("DEBUG: Writing encrypted data, length: {}", encrypted.len());
        file.write_all(&encrypted)?;
        
        println!("DEBUG: Vault saved successfully");
        Ok(())
    }

    pub fn add_credential(&mut self, credential: Credential) -> Result<()> {
        let service = credential.service().to_lowercase();
        let entry = self
            .vault
            .credentials
            .entry(service)
            .or_insert_with(Vec::new);

        // Check if credential already exists
        if entry
            .iter()
            .any(|c| c.username().to_lowercase() == credential.username().to_lowercase())
        {
            return Err(AppError::CredentialError(format!(
                "Credential for '{}' with username '{}' already exists",
                credential.service(),
                credential.username()
            ))
            .into());
        }

        entry.push(credential);
        self.vault.metadata.update_timestamp();
        self.save()?;

        Ok(())
    }

    pub fn get_credential(&self, service: &str, username: Option<&str>) -> Result<Credential> {
        let service = service.to_lowercase();
        let credentials = self
            .vault
            .credentials
            .get(&service)
            .ok_or_else(|| AppError::CredentialError(format!("No credentials found for '{}'", service)))?;

        match username {
            Some(username) => {
                let username = username.to_lowercase();
                credentials
                    .iter()
                    .find(|c| c.username().to_lowercase() == username)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::CredentialError(format!(
                            "No credential found for '{}' with username '{}'",
                            service, username
                        ))
                        .into()
                    })
            }
            None => {
                if credentials.len() == 1 {
                    Ok(credentials[0].clone())
                } else {
                    Err(AppError::CredentialError(format!(
                        "Multiple credentials found for '{}'. Please specify a username.",
                        service
                    ))
                    .into())
                }
            }
        }
    }

    pub fn remove_credential(&mut self, service: &str, username: Option<&str>) -> Result<()> {
        let service = service.to_lowercase();
        
        if !self.vault.credentials.contains_key(&service) {
            return Err(AppError::CredentialError(format!("No credentials found for '{}'", service)).into());
        }

        match username {
            Some(username) => {
                let username = username.to_lowercase();
                let credentials = self.vault.credentials.get_mut(&service).unwrap();
                
                let position = credentials
                    .iter()
                    .position(|c| c.username().to_lowercase() == username)
                    .ok_or_else(|| {
                        AppError::CredentialError(format!(
                            "No credential found for '{}' with username '{}'",
                            service, username
                        ))
                    })?;
                
                credentials.remove(position);
                
                // Remove the service entry if no credentials remain
                if credentials.is_empty() {
                    self.vault.credentials.remove(&service);
                }
            }
            None => {
                // If no username provided, check if there's only one credential
                let credentials = self.vault.credentials.get(&service).unwrap();
                
                if credentials.len() != 1 {
                    return Err(AppError::CredentialError(format!(
                        "Multiple credentials found for '{}'. Please specify a username.",
                        service
                    ))
                    .into());
                }
                
                // Only one credential, so remove the entire service
                self.vault.credentials.remove(&service);
            }
        }

        self.vault.metadata.update_timestamp();
        self.save()?;

        Ok(())
    }

    pub fn list_services(&self) -> Vec<String> {
        self.vault.credentials.keys().cloned().collect()
    }

    pub fn list_credentials_for_service(&self, service: &str) -> Result<Vec<Credential>> {
        let service = service.to_lowercase();
        self.vault
            .credentials
            .get(&service)
            .cloned()
            .ok_or_else(|| AppError::CredentialError(format!("No credentials found for '{}'", service)).into())
    }

    pub fn change_master_password(&mut self, new_master_password: &str) -> Result<()> {
        let salt = Crypto::generate_salt();
        let new_master_key = MasterKey::new(new_master_password, &salt)?;
        
        // Update the salt in the vault metadata
        self.vault.metadata = VaultMetadata::new(salt);
        
        // Update the master key in memory
        self.master_key = new_master_key;
        
        // Save the vault using the updated master key and salt from metadata
        self.save()?;
        
        Ok(())
    }

    pub fn update_credential(
        &mut self,
        service: &str,
        username: &str,
        password: Option<String>,
        notes: Option<String>,
    ) -> Result<()> {
        let service = service.to_lowercase();
        let username = username.to_lowercase();

        let credentials = self
            .vault
            .credentials
            .get_mut(&service)
            .ok_or_else(|| AppError::CredentialError(format!("No credentials found for '{}'", service)))?;

        let credential = credentials
            .iter_mut()
            .find(|c| c.username().to_lowercase() == username)
            .ok_or_else(|| {
                AppError::CredentialError(format!(
                    "No credential found for '{}' with username '{}'",
                    service, username
                ))
            })?;

        if let Some(password) = password {
            credential.update_password(Some(password));
        }

        if let Some(notes) = notes {
            credential.update_notes(Some(notes));
        }

        self.vault.metadata.update_timestamp();
        self.save()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    // Helper function to create a temporary directory
    fn setup() -> (tempfile::TempDir, MasterKey) {
        let dir = tempdir().unwrap();
        let salt = Crypto::generate_salt();
        let master_key = MasterKey::new("test_password", &salt).unwrap();
        (dir, master_key)
    }
    
    #[test]
    fn test_add_get_credential() {
        let (dir, _) = setup();
        let db_path = dir.path().join("vault.enc");
        
        // Override the DB_PATH for testing
        let _guard = std::env::set_var("DB_PATH", db_path.to_str().unwrap());
        
        let mut manager = CredentialManager::initialize("test_password", true).unwrap();
        
        let credential = Credential::new(
            "Test Service".to_string(),
            "testuser".to_string(),
            Some("password123".to_string()),
            Some("Test notes".to_string()),
        );
        
        manager.add_credential(credential).unwrap();
        
        let retrieved = manager.get_credential("Test Service", None).unwrap();
        
        assert_eq!(retrieved.service(), "Test Service");
        assert_eq!(retrieved.username(), "testuser");
        assert_eq!(retrieved.password(), Some("password123"));
        assert_eq!(retrieved.notes(), Some("Test notes"));
    }
    
    #[test]
    fn test_case_insensitive_search() {
        let (dir, _) = setup();
        let db_path = dir.path().join("vault.enc");
        
        // Override the DB_PATH for testing
        let _guard = std::env::set_var("DB_PATH", db_path.to_str().unwrap());
        
        let mut manager = CredentialManager::initialize("test_password", true).unwrap();
        
        let credential = Credential::new(
            "GitHub".to_string(),
            "DevUser".to_string(),
            Some("securepass".to_string()),
            None,
        );
        
        manager.add_credential(credential).unwrap();
        
        // Check case-insensitive search
        let retrieved = manager.get_credential("github", Some("devuser")).unwrap();
        
        assert_eq!(retrieved.service(), "GitHub");
        assert_eq!(retrieved.username(), "DevUser");
    }
} 