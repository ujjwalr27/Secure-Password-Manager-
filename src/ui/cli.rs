use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use rpassword::prompt_password;
use std::fs;

use crate::credential_manager::{Credential, CredentialManager};
use crate::password_gen::PasswordGenerator;
use crate::utils::constants::DATA_DIR;
use crate::utils::errors::AppError;

pub fn handle_command(command: impl Into<Command>) -> Result<()> {
    match command.into() {
        Command::Init { force } => initialize(force),
        Command::Add {
            service,
            username,
            password,
            generate,
            length,
            symbols,
            numbers,
            uppercase,
        } => add_credential(
            service, username, password, generate, length, symbols, numbers, uppercase,
        ),
        Command::Get {
            service,
            username,
            show,
        } => get_credential(service, username, show),
        Command::List { service } => list_credentials(service),
        Command::Remove {
            service,
            username,
            force,
        } => remove_credential(service, username, force),
        Command::Generate {
            length,
            symbols,
            numbers,
            uppercase,
        } => generate_password(length, symbols, numbers, uppercase),
        Command::ChangeMasterPassword { new } => change_master_password(new),
        Command::Update {
            service,
            username,
            password,
            notes,
        } => update_credential(service, username, password, notes),
    }
}

fn initialize(force: bool) -> Result<()> {
    if DATA_DIR.exists() && !force {
        println!(
            "{}",
            "A password vault already exists.".yellow()
        );
        println!("Use --force to overwrite the existing vault (this will delete all stored credentials).");
        return Ok(());
    }

    fs::create_dir_all(&*DATA_DIR)?;

    println!("Setting up a new secure password vault.");
    println!("Please choose a strong master password. This password cannot be recovered if forgotten.");

    let master_password = prompt_for_master_password(true)?;
    CredentialManager::initialize(&master_password, force)?;

    println!(
        "{}",
        "Password vault has been successfully initialized.".green()
    );
    println!("Your vault is located at: {}", DATA_DIR.display());

    Ok(())
}

fn add_credential(
    service: String,
    username: String,
    password: Option<String>,
    generate: bool,
    length: usize,
    symbols: bool,
    numbers: bool,
    uppercase: bool,
) -> Result<()> {
    let master_password = prompt_password("Enter master password: ")?;
    let mut manager = CredentialManager::load(&master_password)?;

    let password = if generate {
        let generator = PasswordGenerator::new(length, true, uppercase, numbers, symbols);
        let generated = generator.generate();
        println!("Generated a secure password.");
        Some(generated)
    } else if let Some(pass) = password {
        Some(pass)
    } else {
        let pass = prompt_password("Enter password (or leave empty to be prompted to generate): ")?;
        if pass.is_empty() {
            println!("No password provided. Generating a secure password...");
            let generator = PasswordGenerator::new(length, true, uppercase, numbers, symbols);
            let generated = generator.generate();
            println!("Generated a secure password.");
            Some(generated)
        } else {
            Some(pass)
        }
    };

    let notes = prompt_for_notes()?;
    let credential = Credential::new(service.clone(), username.clone(), password, notes);

    manager.add_credential(credential)?;

    println!(
        "{}",
        format!("Credential for '{}' with username '{}' added successfully.", service, username).green()
    );

    Ok(())
}

fn get_credential(service: String, username: Option<String>, show: bool) -> Result<()> {
    let master_password = prompt_password("Enter master password: ")?;
    let manager = CredentialManager::load(&master_password)?;

    let credential = manager.get_credential(&service, username.as_deref())?;

    println!();
    println!("Service: {}", credential.service().cyan());
    println!("Username: {}", credential.username().cyan());

    if let Some(password) = credential.password() {
        if show {
            println!("Password: {}", password.cyan());
        } else {
            println!("Password: {}", "[hidden, use --show to reveal]".yellow());
            // Add copy to clipboard functionality in the future
        }
    } else {
        println!("Password: {}", "[not set]".red());
    }

    if let Some(notes) = credential.notes() {
        println!("Notes: {}", notes);
    }

    println!("Created: {}", credential.created_at());
    println!("Last updated: {}", credential.updated_at());

    Ok(())
}

fn list_credentials(service: Option<String>) -> Result<()> {
    let master_password = prompt_password("Enter master password: ")?;
    let manager = CredentialManager::load(&master_password)?;

    match service {
        Some(service) => {
            // List credentials for a specific service
            let credentials = manager.list_credentials_for_service(&service)?;
            
            println!("Credentials for {}: ", service.cyan());
            println!("{}", "=".repeat(40));
            
            for credential in credentials {
                println!("Username: {}", credential.username().cyan());
                println!("Created: {}", credential.created_at());
                println!("Last updated: {}", credential.updated_at());
                println!("{}", "-".repeat(30));
            }
        }
        None => {
            // List all services
            let services = manager.list_services();
            
            if services.is_empty() {
                println!("{}", "No credentials stored.".yellow());
                return Ok(());
            }
            
            println!("Available services:");
            println!("{}", "=".repeat(40));
            
            for (i, service) in services.iter().enumerate() {
                println!("{}. {}", i + 1, service.cyan());
            }
        }
    }

    Ok(())
}

fn remove_credential(service: String, username: Option<String>, force: bool) -> Result<()> {
    let master_password = prompt_password("Enter master password: ")?;
    let mut manager = CredentialManager::load(&master_password)?;

    if !force {
        // Show credential details before removal
        let credential = manager.get_credential(&service, username.as_deref())?;
        
        println!("About to remove the following credential:");
        println!("Service: {}", credential.service().cyan());
        println!("Username: {}", credential.username().cyan());
        
        if !confirm_action("Are you sure you want to remove this credential?")? {
            println!("{}", "Removal canceled.".yellow());
            return Ok(());
        }
    }

    manager.remove_credential(&service, username.as_deref())?;
    
    println!(
        "{}",
        format!("Credential for '{}' removed successfully.", service).green()
    );

    Ok(())
}

fn generate_password(length: usize, symbols: bool, numbers: bool, uppercase: bool) -> Result<()> {
    let generator = PasswordGenerator::new(length, true, uppercase, numbers, symbols);
    let password = generator.generate();

    println!("Generated Password: {}", password.cyan());
    println!();
    println!("Password properties:");
    println!("Length: {}", length);
    println!("Contains uppercase letters: {}", if uppercase { "Yes".green() } else { "No".red() });
    println!("Contains numbers: {}", if numbers { "Yes".green() } else { "No".red() });
    println!("Contains symbols: {}", if symbols { "Yes".green() } else { "No".red() });

    Ok(())
}

fn change_master_password(new_password: String) -> Result<()> {
    println!("Changing master password");
    println!("{}",
        "WARNING: If you forget your new master password, you will lose access to all your credentials."
            .red()
            .bold()
    );

    let current_password = prompt_password("Enter current master password: ")?;
    let mut manager = CredentialManager::load(&current_password)?;

    manager.change_master_password(&new_password)?;

    println!(
        "{}",
        "Master password has been changed successfully.".green()
    );

    Ok(())
}

fn prompt_for_master_password(confirm: bool) -> Result<String> {
    let password = prompt_password("Enter master password: ")?;
    
    if password.is_empty() {
        return Err(AppError::UserInputError("Master password cannot be empty".to_string()).into());
    }
    
    if password.len() < 8 {
        println!("{}", "Warning: Master password is less than 8 characters. This is not recommended.".yellow());
    }
    
    if confirm {
        let confirm_password = prompt_password("Confirm master password: ")?;
        
        if password != confirm_password {
            return Err(AppError::UserInputError("Passwords do not match".to_string()).into());
        }
    }
    
    Ok(password)
}

fn prompt_for_notes() -> Result<Option<String>> {
    println!("Enter notes (optional, press Enter to skip):");
    let mut notes = String::new();
    std::io::stdin().read_line(&mut notes)?;
    
    let notes = notes.trim();
    if notes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(notes.to_string()))
    }
}

fn confirm_action(prompt: &str) -> Result<bool> {
    println!("{} (y/n): ", prompt);
    let mut response = String::new();
    std::io::stdin().read_line(&mut response)?;
    
    let response = response.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

fn update_credential(
    service: String,
    username: String,
    password: Option<String>,
    notes: Option<String>,
) -> Result<()> {
    let master_password = prompt_password("Enter master password: ")?;
    let mut manager = CredentialManager::load(&master_password)?;

    // Show the current credential before updating
    let credential = manager.get_credential(&service, Some(&username))?;
    
    println!("Updating credential for:");
    println!("Service: {}", credential.service().cyan());
    println!("Username: {}", credential.username().cyan());
    
    // Update the credential
    manager.update_credential(&service, &username, password.clone(), notes.clone())?;
    
    println!("{}", "Credential updated successfully.".green());
    
    // If password was updated, show confirmation
    if password.is_some() {
        println!("Password has been updated.");
    }
    
    // If notes were updated, show confirmation
    if notes.is_some() {
        println!("Notes have been updated.");
    }
    
    Ok(())
}

// Command enum for internal use
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize the password manager with a master password
    Init {
        /// Force re-initialization (warning: this will delete all existing data)
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        force: bool,
    },
    /// Add a new credential
    Add {
        /// Service name
        #[clap(short, long)]
        service: String,
        /// Username
        #[clap(short, long)]
        username: String,
        /// Password (if not provided, will be prompted securely)
        #[clap(short, long)]
        password: Option<String>,
        /// Generate a random password
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        generate: bool,
        /// Password length (used with --generate)
        #[clap(short, long, default_value = "16")]
        length: usize,
        /// Include symbols in generated password
        #[clap(long, action = clap::ArgAction::SetTrue)]
        symbols: bool,
        /// Include numbers in generated password
        #[clap(long, default_value = "true")]
        numbers: bool,
        /// Include uppercase letters in generated password
        #[clap(long, default_value = "true")]
        uppercase: bool,
    },
    /// Get a credential
    Get {
        /// Service name
        #[clap(short, long)]
        service: String,
        /// Username (optional if service has only one credential)
        #[clap(short, long)]
        username: Option<String>,
        /// Show the password in plain text (not recommended in shared terminals)
        #[clap(long, action = clap::ArgAction::SetTrue)]
        show: bool,
    },
    /// List all services or credentials for a specific service
    List {
        /// Service name (optional)
        #[clap(short, long)]
        service: Option<String>,
    },
    /// Remove a credential
    Remove {
        /// Service name
        #[clap(short, long)]
        service: String,
        /// Username (optional if service has only one credential)
        #[clap(short, long)]
        username: Option<String>,
        /// Skip confirmation
        #[clap(short, long, action = clap::ArgAction::SetTrue)]
        force: bool,
    },
    /// Generate a random password
    Generate {
        /// Password length
        #[clap(short, long, default_value = "16")]
        length: usize,
        /// Include symbols in generated password
        #[clap(long, action = clap::ArgAction::SetTrue)]
        symbols: bool,
        /// Include numbers in generated password
        #[clap(long, default_value = "true")]
        numbers: bool,
        /// Include uppercase letters in generated password
        #[clap(long, default_value = "true")]
        uppercase: bool,
    },
    /// Change the master password
    #[clap(name = "change-master-password", aliases = ["change-master"])]
    ChangeMasterPassword {
        /// New master password
        #[clap(short, long)]
        new: String,
    },
    /// Update an existing credential
    Update {
        /// Service name
        #[clap(short, long)]
        service: String,
        /// Username
        #[clap(short, long)]
        username: String,
        /// New password (optional)
        #[clap(short, long)]
        password: Option<String>,
        /// New notes (optional)
        #[clap(short, long)]
        notes: Option<String>,
    },
} 