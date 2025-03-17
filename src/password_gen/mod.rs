use rand::{distributions::Uniform, prelude::*};
use zeroize::Zeroize;

const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBER_CHARS: &str = "0123456789";
const SYMBOL_CHARS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";

#[derive(Debug, Clone)]
pub struct PasswordGenerator {
    length: usize,
    include_lowercase: bool,
    include_uppercase: bool,
    include_numbers: bool,
    include_symbols: bool,
}

impl Default for PasswordGenerator {
    fn default() -> Self {
        Self {
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_numbers: true,
            include_symbols: false,
        }
    }
}

impl PasswordGenerator {
    pub fn new(
        length: usize,
        include_lowercase: bool,
        include_uppercase: bool,
        include_numbers: bool,
        include_symbols: bool,
    ) -> Self {
        Self {
            length,
            include_lowercase,
            include_uppercase,
            include_numbers,
            include_symbols,
        }
    }
    
    pub fn generate(&self) -> String {
        if self.length == 0 {
            return String::new();
        }
        
        let mut charset = String::new();
        
        if self.include_lowercase {
            charset.push_str(LOWERCASE_CHARS);
        }
        
        if self.include_uppercase {
            charset.push_str(UPPERCASE_CHARS);
        }
        
        if self.include_numbers {
            charset.push_str(NUMBER_CHARS);
        }
        
        if self.include_symbols {
            charset.push_str(SYMBOL_CHARS);
        }
        
        // Fallback to lowercase letters if nothing is selected
        if charset.is_empty() {
            charset.push_str(LOWERCASE_CHARS);
        }
        
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, charset.len());
        
        // Convert charset to a vector of characters for efficient indexing
        let charset: Vec<char> = charset.chars().collect();
        
        let mut password = String::with_capacity(self.length);
        for _ in 0..self.length {
            let idx = range.sample(&mut rng);
            password.push(charset[idx]);
        }
        
        // Ensure password has at least one character from each included character set
        // if the password is long enough
        if self.length >= 4 && (self.include_lowercase || self.include_uppercase || self.include_numbers || self.include_symbols) {
            let mut has_to_fix = false;
            
            if self.include_lowercase && !password.chars().any(|c| LOWERCASE_CHARS.contains(c)) {
                has_to_fix = true;
            }
            
            if self.include_uppercase && !password.chars().any(|c| UPPERCASE_CHARS.contains(c)) {
                has_to_fix = true;
            }
            
            if self.include_numbers && !password.chars().any(|c| NUMBER_CHARS.contains(c)) {
                has_to_fix = true;
            }
            
            if self.include_symbols && !password.chars().any(|c| SYMBOL_CHARS.contains(c)) {
                has_to_fix = true;
            }
            
            if has_to_fix {
                // If we need to fix, just regenerate the password
                // This is simpler than trying to fix it directly
                return self.generate();
            }
        }
        
        password
    }
}

#[derive(Debug)]
pub struct Password {
    value: String,
}

impl Drop for Password {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_default() {
        let generator = PasswordGenerator::default();
        let password = generator.generate();
        
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| LOWERCASE_CHARS.contains(c)));
        assert!(password.chars().any(|c| UPPERCASE_CHARS.contains(c)));
        assert!(password.chars().any(|c| NUMBER_CHARS.contains(c)));
        assert!(!password.chars().any(|c| SYMBOL_CHARS.contains(c)));
    }
    
    #[test]
    fn test_generate_only_lowercase() {
        let generator = PasswordGenerator::new(10, true, false, false, false);
        let password = generator.generate();
        
        assert_eq!(password.len(), 10);
        assert!(password.chars().all(|c| LOWERCASE_CHARS.contains(c)));
    }
    
    #[test]
    fn test_generate_with_symbols() {
        let generator = PasswordGenerator::new(20, true, true, true, true);
        let password = generator.generate();
        
        assert_eq!(password.len(), 20);
        
        // Check that we have at least one of each character type
        assert!(password.chars().any(|c| LOWERCASE_CHARS.contains(c)));
        assert!(password.chars().any(|c| UPPERCASE_CHARS.contains(c)));
        assert!(password.chars().any(|c| NUMBER_CHARS.contains(c)));
        assert!(password.chars().any(|c| SYMBOL_CHARS.contains(c)));
    }
    
    #[test]
    fn test_zero_length() {
        let generator = PasswordGenerator::new(0, true, true, true, true);
        let password = generator.generate();
        
        assert_eq!(password.len(), 0);
    }
} 