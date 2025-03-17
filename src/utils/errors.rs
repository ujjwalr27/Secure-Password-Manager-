use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    #[error("Credential error: {0}")]
    CredentialError(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("User input error: {0}")]
    UserInputError(String),
    #[error("Application not initialized. Please run 'init' first.")]
    NotInitialized
} 