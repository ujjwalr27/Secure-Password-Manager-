use std::path::PathBuf;
use directories::ProjectDirs;
use lazy_static::lazy_static;

pub const APP_NAME: &str = "secure_password_manager";
pub const APP_AUTHOR: &str = "Secure Password Manager Team";
pub const DB_FILENAME: &str = "vault.enc";
pub const SALT_SIZE: usize = 16; // bytes
pub const KEY_LEN: usize = 32; // bytes (256 bits)
pub const TAG_SIZE: usize = 16; // bytes
pub const MEMORY_COST: u32 = 19456; // ~19MB
pub const TIME_COST: u32 = 2;
pub const PARALLELISM: u32 = 1;

lazy_static! {
    pub static ref DATA_DIR: PathBuf = {
        let project_dirs = ProjectDirs::from("com", APP_AUTHOR, APP_NAME)
            .expect("Could not determine app data directory");
        project_dirs.data_dir().to_path_buf()
    };
    
    pub static ref DB_PATH: PathBuf = {
        DATA_DIR.join(DB_FILENAME)
    };
} 