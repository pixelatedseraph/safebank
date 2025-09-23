//! SafeBank - A lightweight cybersecurity framework for rural digital banking
//! 
//! This framework provides essential security features optimized for low-resource environments:
//! - User authentication with multi-factor support
//! - Fraud detection through behavioral pattern analysis
//! - Transaction security with lightweight encryption
//! - Offline capability and data synchronization

pub mod auth;
pub mod fraud_detection;
pub mod transaction;
pub mod config;
pub mod errors;
pub mod utils;

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Main SafeBank framework structure
#[derive(Debug)]
pub struct SafeBankFramework {
    config: config::SafeBankConfig,
    auth_manager: auth::AuthManager,
    fraud_detector: fraud_detection::FraudDetector,
    transaction_manager: transaction::TransactionManager,
}

/// User profile for rural banking context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub phone_number: String,
    pub pin_hash: String,
    pub device_info: DeviceInfo,
    pub behavioral_profile: BehavioralProfile,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_attempts: u32,
    pub is_locked: bool,
}

/// Device information for security tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_type: String,
    pub os_version: Option<String>,
    pub app_version: String,
    pub is_trusted: bool,
    pub registered_at: DateTime<Utc>,
}

/// Behavioral pattern for fraud detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralProfile {
    pub typical_transaction_amount: f64,
    pub typical_transaction_times: Vec<u8>, // Hour of day (0-23)
    pub common_recipients: Vec<String>,
    pub geographic_patterns: Vec<String>,
    pub usage_frequency: f64, // transactions per day
}

/// Transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub transaction_id: Uuid,
    pub user_id: Uuid,
    pub amount: f64,
    pub recipient: String,
    pub transaction_type: TransactionType,
    pub timestamp: DateTime<Utc>,
    pub location: Option<String>,
    pub device_id: String,
    pub fraud_score: f64,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    Transfer,
    Payment,
    Withdrawal,
    Deposit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Approved,
    Rejected,
    Flagged,
    RequiresApproval,
}

impl SafeBankFramework {
    pub fn new(config: config::SafeBankConfig) -> Self {
        Self {
            auth_manager: auth::AuthManager::new(&config),
            fraud_detector: fraud_detection::FraudDetector::new(&config),
            transaction_manager: transaction::TransactionManager::new(&config),
            config,
        }
    }

    /// Initialize a new user profile
    pub fn register_user(&mut self, phone_number: String, pin: String, device_info: DeviceInfo) -> Result<UserProfile, errors::SafeBankError> {
        self.auth_manager.register_user(phone_number, pin, device_info)
    }

    /// Authenticate user with PIN and device verification
    pub fn authenticate_user(&mut self, phone_number: &str, pin: &str, device_id: &str) -> Result<UserProfile, errors::SafeBankError> {
        self.auth_manager.authenticate(phone_number, pin, device_id)
    }

    /// Process a transaction with fraud detection
    pub fn process_transaction(&mut self, user_id: Uuid, amount: f64, recipient: String, transaction_type: TransactionType) -> Result<Transaction, errors::SafeBankError> {
        // Get user profile for fraud analysis
        let user = self.auth_manager.get_user_by_id(user_id)?;
        
        // Create transaction
        let mut transaction = Transaction {
            transaction_id: Uuid::new_v4(),
            user_id,
            amount,
            recipient: recipient.clone(),
            transaction_type,
            timestamp: Utc::now(),
            location: None,
            device_id: user.device_info.device_id.clone(),
            fraud_score: 0.0,
            status: TransactionStatus::Pending,
        };

        // Run fraud detection
        transaction.fraud_score = self.fraud_detector.analyze_transaction(&transaction, &user)?;
        
        // Determine transaction status based on fraud score
        transaction.status = if transaction.fraud_score > self.config.fraud_threshold_high {
            TransactionStatus::Rejected
        } else if transaction.fraud_score > self.config.fraud_threshold_medium {
            TransactionStatus::RequiresApproval
        } else {
            TransactionStatus::Approved
        };

        // Process transaction
        self.transaction_manager.process_transaction(transaction)
    }

    /// Update user behavioral profile based on transaction history
    pub fn update_behavioral_profile(&mut self, user_id: Uuid) -> Result<(), errors::SafeBankError> {
        let transactions = self.transaction_manager.get_user_transactions(user_id)?;
        self.fraud_detector.update_behavioral_profile(user_id, &transactions)?;
        Ok(())
    }

    /// Get fraud statistics for monitoring
    pub fn get_fraud_statistics(&self) -> HashMap<String, f64> {
        self.fraud_detector.get_statistics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_initialization() {
        let config = config::SafeBankConfig::default();
        let framework = SafeBankFramework::new(config);
        // Basic initialization test
        assert!(framework.config.max_failed_attempts > 0);
    }
}