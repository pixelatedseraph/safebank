//! Authentication module for SafeBank framework
//! Provides secure user authentication optimized for rural environments

use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use uuid::Uuid;

use crate::{UserProfile, DeviceInfo, BehavioralProfile, config::SafeBankConfig, errors::{SafeBankError, Result}};

#[derive(Debug)]
pub struct AuthManager {
    config: SafeBankConfig,
    users: HashMap<String, UserProfile>, // phone_number -> UserProfile
    user_by_id: HashMap<Uuid, UserProfile>, // user_id -> UserProfile
    failed_attempts: HashMap<String, (u32, DateTime<Utc>)>, // phone_number -> (count, last_attempt)
}

impl AuthManager {
    pub fn new(config: &SafeBankConfig) -> Self {
        Self {
            config: config.clone(),
            users: HashMap::new(),
            user_by_id: HashMap::new(),
            failed_attempts: HashMap::new(),
        }
    }

    /// Register a new user with phone number and PIN
    pub fn register_user(&mut self, phone_number: String, pin: String, device_info: DeviceInfo) -> Result<UserProfile> {
        // Validate phone number format (basic validation)
        if !self.is_valid_phone_number(&phone_number) {
            return Err(SafeBankError::AuthenticationFailed {
                message: "Invalid phone number format".to_string(),
            });
        }

        // Check if user already exists
        if self.users.contains_key(&phone_number) {
            return Err(SafeBankError::AuthenticationFailed {
                message: "User already exists".to_string(),
            });
        }

        // Validate PIN
        if !self.is_valid_pin(&pin) {
            return Err(SafeBankError::InvalidPin);
        }

        // Hash PIN using Argon2 (memory-hard function suitable for low-end devices)
        let pin_hash = self.hash_pin(&pin)?;

        // Create user profile
        let user_profile = UserProfile {
            user_id: Uuid::new_v4(),
            phone_number: phone_number.clone(),
            pin_hash,
            device_info,
            behavioral_profile: BehavioralProfile {
                typical_transaction_amount: 0.0,
                typical_transaction_times: vec![],
                common_recipients: vec![],
                geographic_patterns: vec![],
                usage_frequency: 0.0,
            },
            created_at: Utc::now(),
            last_login: None,
            failed_attempts: 0,
            is_locked: false,
        };

        // Store user
        self.user_by_id.insert(user_profile.user_id, user_profile.clone());
        self.users.insert(phone_number, user_profile.clone());

        Ok(user_profile)
    }

    /// Authenticate user with phone number, PIN, and device verification
    pub fn authenticate(&mut self, phone_number: &str, pin: &str, device_id: &str) -> Result<UserProfile> {
        // Check if account is temporarily locked due to failed attempts
        if self.is_account_locked(phone_number) {
            return Err(SafeBankError::AccountLocked);
        }

        // Get user profile
        let mut user = self.users.get(phone_number)
            .ok_or_else(|| SafeBankError::UserNotFound {
                user_id: phone_number.to_string(),
            })?.clone();

        // Check if account is locked
        if user.is_locked {
            return Err(SafeBankError::AccountLocked);
        }

        // Verify PIN
        if !self.verify_pin(pin, &user.pin_hash)? {
            self.record_failed_attempt(phone_number);
            return Err(SafeBankError::AuthenticationFailed {
                message: "Invalid PIN".to_string(),
            });
        }

        // Device verification (if enabled)
        if self.config.require_device_verification {
            if user.device_info.device_id != device_id {
                // For rural banking, we might want to allow device changes but flag them
                if !user.device_info.is_trusted {
                    return Err(SafeBankError::UnrecognizedDevice {
                        device_id: device_id.to_string(),
                    });
                }
            }
        }

        // Update successful login
        user.last_login = Some(Utc::now());
        user.failed_attempts = 0;
        
        // Clear failed attempts
        self.failed_attempts.remove(phone_number);

        // Update stored user
        self.users.insert(phone_number.to_string(), user.clone());
        self.user_by_id.insert(user.user_id, user.clone());

        Ok(user)
    }

    /// Get user by ID
    pub fn get_user_by_id(&self, user_id: Uuid) -> Result<UserProfile> {
        self.user_by_id.get(&user_id)
            .cloned()
            .ok_or_else(|| SafeBankError::UserNotFound {
                user_id: user_id.to_string(),
            })
    }

    /// Update user's behavioral profile
    pub fn update_user_profile(&mut self, user_id: Uuid, behavioral_profile: BehavioralProfile) -> Result<()> {
        if let Some(user) = self.user_by_id.get_mut(&user_id) {
            user.behavioral_profile = behavioral_profile;
            // Also update in phone number map
            self.users.insert(user.phone_number.clone(), user.clone());
            Ok(())
        } else {
            Err(SafeBankError::UserNotFound {
                user_id: user_id.to_string(),
            })
        }
    }

    /// Trust a device for a user
    pub fn trust_device(&mut self, user_id: Uuid, device_id: String) -> Result<()> {
        if let Some(user) = self.user_by_id.get_mut(&user_id) {
            if user.device_info.device_id == device_id {
                user.device_info.is_trusted = true;
                self.users.insert(user.phone_number.clone(), user.clone());
            }
            Ok(())
        } else {
            Err(SafeBankError::UserNotFound {
                user_id: user_id.to_string(),
            })
        }
    }

    /// Check if account is temporarily locked due to failed attempts
    fn is_account_locked(&self, phone_number: &str) -> bool {
        if let Some((count, last_attempt)) = self.failed_attempts.get(phone_number) {
            if *count >= self.config.max_failed_attempts {
                let lockout_duration = Duration::minutes(self.config.lockout_duration_minutes as i64);
                return Utc::now() - *last_attempt < lockout_duration;
            }
        }
        false
    }

    /// Record a failed authentication attempt
    fn record_failed_attempt(&mut self, phone_number: &str) {
        let count = self.failed_attempts
            .get(phone_number)
            .map(|(count, _)| count + 1)
            .unwrap_or(1);
        
        self.failed_attempts.insert(phone_number.to_string(), (count, Utc::now()));
    }

    /// Validate phone number format (basic validation for rural context)
    fn is_valid_phone_number(&self, phone_number: &str) -> bool {
        // Basic validation: should be 10-15 digits, may start with +
        let clean_number = phone_number.replace(['+', '-', ' '], "");
        clean_number.len() >= 10 && clean_number.len() <= 15 && clean_number.chars().all(|c| c.is_ascii_digit())
    }

    /// Validate PIN format
    fn is_valid_pin(&self, pin: &str) -> bool {
        if self.config.pin_complexity_required {
            // Complex PIN validation
            pin.len() >= 6 && pin.chars().all(|c| c.is_ascii_digit()) && !self.is_sequential(pin)
        } else {
            // Simple PIN validation for rural users
            pin.len() >= 4 && pin.len() <= 6 && pin.chars().all(|c| c.is_ascii_digit())
        }
    }

    /// Check if PIN is sequential (e.g., 1234, 9876)
    fn is_sequential(&self, pin: &str) -> bool {
        if pin.len() < 3 {
            return false;
        }
        
        let chars: Vec<char> = pin.chars().collect();
        let mut is_ascending = true;
        let mut is_descending = true;
        
        for i in 1..chars.len() {
            let current = chars[i].to_digit(10).unwrap_or(0);
            let previous = chars[i-1].to_digit(10).unwrap_or(0);
            
            if current != previous + 1 {
                is_ascending = false;
            }
            if current != previous.saturating_sub(1) {
                is_descending = false;
            }
        }
        
        is_ascending || is_descending
    }

    /// Hash PIN using Argon2
    fn hash_pin(&self, pin: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = if self.config.enable_lightweight_encryption {
            // Lighter parameters for low-end devices
            Argon2::default()
        } else {
            Argon2::default()
        };
        
        let password_hash = argon2
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|e| SafeBankError::CryptographyError {
                message: format!("Failed to hash PIN: {}", e),
            })?;
        
        Ok(password_hash.to_string())
    }

    /// Verify PIN against hash
    fn verify_pin(&self, pin: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| SafeBankError::CryptographyError {
                message: format!("Failed to parse hash: {}", e),
            })?;
        
        let argon2 = Argon2::default();
        Ok(argon2.verify_password(pin.as_bytes(), &parsed_hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SafeBankConfig;

    fn create_test_device_info() -> DeviceInfo {
        DeviceInfo {
            device_id: "test-device-123".to_string(),
            device_type: "smartphone".to_string(),
            os_version: Some("Android 8.0".to_string()),
            app_version: "1.0.0".to_string(),
            is_trusted: false,
            registered_at: Utc::now(),
        }
    }

    #[test]
    fn test_user_registration() {
        let config = SafeBankConfig::default();
        let mut auth_manager = AuthManager::new(&config);
        
        let result = auth_manager.register_user(
            "+1234567890".to_string(),
            "1234".to_string(),
            create_test_device_info(),
        );
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_authentication() {
        let config = SafeBankConfig::default();
        let mut auth_manager = AuthManager::new(&config);
        
        // Register user first
        let user = auth_manager.register_user(
            "+1234567890".to_string(),
            "1234".to_string(),
            create_test_device_info(),
        ).unwrap();
        
        // Test authentication
        let auth_result = auth_manager.authenticate(
            "+1234567890",
            "1234",
            &user.device_info.device_id,
        );
        
        assert!(auth_result.is_ok());
    }

    #[test]
    fn test_invalid_pin() {
        let config = SafeBankConfig::default();
        let auth_manager = AuthManager::new(&config);
        
        assert!(!auth_manager.is_valid_pin("123")); // Too short
        assert!(!auth_manager.is_valid_pin("12345678")); // Too long
        assert!(!auth_manager.is_valid_pin("12ab")); // Contains letters
        assert!(auth_manager.is_valid_pin("1234")); // Valid
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let config = SafeBankConfig::default();
        let mut auth_manager = AuthManager::new(&config);
        
        // Register user
        let user = auth_manager.register_user(
            "+1234567890".to_string(),
            "1234".to_string(),
            create_test_device_info(),
        ).unwrap();
        
        // Make multiple failed attempts
        for _ in 0..3 {
            let _ = auth_manager.authenticate(
                "+1234567890",
                "wrong",
                &user.device_info.device_id,
            );
        }
        
        // Account should be locked now
        assert!(auth_manager.is_account_locked("+1234567890"));
    }
}