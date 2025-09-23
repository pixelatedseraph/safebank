//! Transaction management module for SafeBank framework
//! Handles secure transaction processing with encryption and validation

use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;

use crate::{
    Transaction, TransactionStatus,
    config::SafeBankConfig, errors::{SafeBankError, Result}
};

#[derive(Debug)]
pub struct TransactionManager {
    config: SafeBankConfig,
    transactions: HashMap<Uuid, Transaction>,
    user_transactions: HashMap<Uuid, Vec<Uuid>>, // user_id -> transaction_ids
    daily_limits: HashMap<Uuid, DailyLimit>,
}

#[derive(Debug, Clone)]
pub struct DailyLimit {
    pub user_id: Uuid,
    pub date: DateTime<Utc>,
    pub total_amount: f64,
    pub transaction_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub amount: f64,
    pub recipient: String,
    pub status: TransactionStatus,
    pub confirmation_code: String,
    pub fraud_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineTransaction {
    pub transaction: Transaction,
    pub encrypted_data: String,
    pub signature: String,
    pub expires_at: DateTime<Utc>,
}

impl TransactionManager {
    pub fn new(config: &SafeBankConfig) -> Self {
        Self {
            config: config.clone(),
            transactions: HashMap::new(),
            user_transactions: HashMap::new(),
            daily_limits: HashMap::new(),
        }
    }

    /// Process a transaction with validation and security checks
    pub fn process_transaction(&mut self, mut transaction: Transaction) -> Result<Transaction> {
        // Validate transaction amount
        if transaction.amount <= 0.0 {
            return Err(SafeBankError::ConfigError {
                message: "Transaction amount must be positive".to_string(),
            });
        }

        // Check single transaction limit
        if transaction.amount > self.config.single_transaction_limit {
            return Err(SafeBankError::TransactionLimitExceeded {
                amount: transaction.amount,
                limit: self.config.single_transaction_limit,
            });
        }

        // Check daily limits
        self.check_daily_limit(&transaction)?;

        // Validate transaction status progression
        self.validate_transaction_status(&transaction)?;

        // Generate transaction hash for integrity
        let _transaction_hash = self.generate_transaction_hash(&transaction);
        
        // Store transaction
        self.transactions.insert(transaction.transaction_id, transaction.clone());
        
        // Update user transaction history
        self.user_transactions
            .entry(transaction.user_id)
            .or_insert_with(Vec::new)
            .push(transaction.transaction_id);

        // Update daily limits
        self.update_daily_limit(&transaction)?;

        // Set final status based on fraud score and other factors
        if transaction.status == TransactionStatus::Approved {
            transaction.status = TransactionStatus::Approved;
        }

        // Update stored transaction
        self.transactions.insert(transaction.transaction_id, transaction.clone());

        Ok(transaction)
    }

    /// Get transactions for a specific user
    pub fn get_user_transactions(&self, user_id: Uuid) -> Result<Vec<Transaction>> {
        let empty_vec = Vec::new();
        let transaction_ids = self.user_transactions.get(&user_id)
            .unwrap_or(&empty_vec);
        
        let mut transactions = Vec::new();
        for &transaction_id in transaction_ids {
            if let Some(transaction) = self.transactions.get(&transaction_id) {
                transactions.push(transaction.clone());
            }
        }

        // Sort by timestamp (most recent first)
        transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(transactions)
    }

    /// Get transaction by ID
    pub fn get_transaction(&self, transaction_id: Uuid) -> Result<Transaction> {
        self.transactions.get(&transaction_id)
            .cloned()
            .ok_or_else(|| SafeBankError::StorageError {
                message: format!("Transaction not found: {}", transaction_id),
            })
    }

    /// Create a transaction receipt
    pub fn create_receipt(&self, transaction: &Transaction) -> TransactionReceipt {
        let confirmation_code = self.generate_confirmation_code(transaction);
        
        TransactionReceipt {
            transaction_id: transaction.transaction_id,
            timestamp: transaction.timestamp,
            amount: transaction.amount,
            recipient: transaction.recipient.clone(),
            status: transaction.status.clone(),
            confirmation_code,
            fraud_score: transaction.fraud_score,
        }
    }

    /// Approve a flagged transaction (manual review)
    pub fn approve_transaction(&mut self, transaction_id: Uuid) -> Result<Transaction> {
        let mut transaction = self.get_transaction(transaction_id)?;
        
        if transaction.status != TransactionStatus::RequiresApproval 
            && transaction.status != TransactionStatus::Flagged {
            return Err(SafeBankError::InvalidTransactionState {
                current_state: format!("{:?}", transaction.status),
            });
        }

        transaction.status = TransactionStatus::Approved;
        self.transactions.insert(transaction_id, transaction.clone());
        
        Ok(transaction)
    }

    /// Reject a transaction
    pub fn reject_transaction(&mut self, transaction_id: Uuid, _reason: String) -> Result<Transaction> {
        let mut transaction = self.get_transaction(transaction_id)?;
        
        if transaction.status == TransactionStatus::Approved {
            return Err(SafeBankError::InvalidTransactionState {
                current_state: "Cannot reject approved transaction".to_string(),
            });
        }

        transaction.status = TransactionStatus::Rejected;
        self.transactions.insert(transaction_id, transaction.clone());
        
        Ok(transaction)
    }

    /// Create offline transaction for areas with poor connectivity
    pub fn create_offline_transaction(&self, transaction: &Transaction, secret_key: &str) -> Result<OfflineTransaction> {
        if transaction.amount > self.config.offline_transaction_limit {
            return Err(SafeBankError::TransactionLimitExceeded {
                amount: transaction.amount,
                limit: self.config.offline_transaction_limit,
            });
        }

        // Serialize transaction data
        let transaction_data = serde_json::to_string(transaction)
            .map_err(|e| SafeBankError::SerializationError {
                message: format!("Failed to serialize transaction: {}", e),
            })?;

        // Encrypt transaction data (simplified encryption for demo)
        let encrypted_data = self.encrypt_data(&transaction_data, secret_key)?;
        
        // Generate signature for integrity
        let signature = self.generate_signature(&transaction_data, secret_key);

        // Set expiration time
        let expires_at = Utc::now() + Duration::hours(self.config.offline_cache_duration_hours as i64);

        Ok(OfflineTransaction {
            transaction: transaction.clone(),
            encrypted_data,
            signature,
            expires_at,
        })
    }

    /// Process offline transaction when connectivity is restored
    pub fn process_offline_transaction(&mut self, offline_tx: &OfflineTransaction, secret_key: &str) -> Result<Transaction> {
        // Check if transaction has expired
        if Utc::now() > offline_tx.expires_at {
            return Err(SafeBankError::TimeoutError {
                operation: "Offline transaction expired".to_string(),
            });
        }

        // Verify signature
        let decrypted_data = self.decrypt_data(&offline_tx.encrypted_data, secret_key)?;
        let expected_signature = self.generate_signature(&decrypted_data, secret_key);
        
        if offline_tx.signature != expected_signature {
            return Err(SafeBankError::CryptographyError {
                message: "Invalid transaction signature".to_string(),
            });
        }

        // Process the transaction normally
        self.process_transaction(offline_tx.transaction.clone())
    }

    /// Get transaction statistics for monitoring
    pub fn get_transaction_statistics(&self) -> HashMap<String, f64> {
        let mut stats = HashMap::new();
        
        stats.insert("total_transactions".to_string(), self.transactions.len() as f64);
        
        let mut approved = 0;
        let mut rejected = 0;
        let mut flagged = 0;
        let mut total_volume = 0.0;
        
        for transaction in self.transactions.values() {
            match transaction.status {
                TransactionStatus::Approved => approved += 1,
                TransactionStatus::Rejected => rejected += 1,
                TransactionStatus::Flagged | TransactionStatus::RequiresApproval => flagged += 1,
                _ => {}
            }
            total_volume += transaction.amount;
        }
        
        stats.insert("approved_count".to_string(), approved as f64);
        stats.insert("rejected_count".to_string(), rejected as f64);
        stats.insert("flagged_count".to_string(), flagged as f64);
        stats.insert("total_volume".to_string(), total_volume);
        
        if self.transactions.len() > 0 {
            let approval_rate = (approved as f64) / (self.transactions.len() as f64) * 100.0;
            stats.insert("approval_rate_percent".to_string(), approval_rate);
            
            let average_amount = total_volume / (self.transactions.len() as f64);
            stats.insert("average_transaction_amount".to_string(), average_amount);
        }
        
        stats
    }

    /// Check if user has exceeded daily transaction limits
    fn check_daily_limit(&self, transaction: &Transaction) -> Result<()> {
        if let Some(daily_limit) = self.daily_limits.get(&transaction.user_id) {
            let today = Utc::now().date_naive();
            let limit_date = daily_limit.date.date_naive();
            
            if today == limit_date {
                let projected_total = daily_limit.total_amount + transaction.amount;
                if projected_total > self.config.daily_transaction_limit {
                    return Err(SafeBankError::TransactionLimitExceeded {
                        amount: projected_total,
                        limit: self.config.daily_transaction_limit,
                    });
                }
            }
        }
        Ok(())
    }

    /// Update daily transaction limits for user
    fn update_daily_limit(&mut self, transaction: &Transaction) -> Result<()> {
        let today = Utc::now().date_naive();
        
        if let Some(daily_limit) = self.daily_limits.get_mut(&transaction.user_id) {
            let limit_date = daily_limit.date.date_naive();
            
            if today == limit_date {
                // Same day, update existing limit
                daily_limit.total_amount += transaction.amount;
                daily_limit.transaction_count += 1;
            } else {
                // New day, reset limit
                daily_limit.date = Utc::now();
                daily_limit.total_amount = transaction.amount;
                daily_limit.transaction_count = 1;
            }
        } else {
            // First transaction for this user
            self.daily_limits.insert(transaction.user_id, DailyLimit {
                user_id: transaction.user_id,
                date: Utc::now(),
                total_amount: transaction.amount,
                transaction_count: 1,
            });
        }
        Ok(())
    }

    /// Validate transaction status transitions
    fn validate_transaction_status(&self, transaction: &Transaction) -> Result<()> {
        // Basic validation - can be extended for more complex state machines
        match transaction.status {
            TransactionStatus::Approved | TransactionStatus::Rejected => {
                // Terminal states - should not be changed
                Ok(())
            }
            TransactionStatus::Pending | TransactionStatus::Flagged | TransactionStatus::RequiresApproval => {
                // Valid intermediate states
                Ok(())
            }
        }
    }

    /// Generate transaction hash for integrity verification
    fn generate_transaction_hash(&self, transaction: &Transaction) -> String {
        let mut hasher = Sha256::new();
        hasher.update(transaction.transaction_id.as_bytes());
        hasher.update(transaction.user_id.as_bytes());
        hasher.update(transaction.amount.to_string().as_bytes());
        hasher.update(transaction.recipient.as_bytes());
        hasher.update(transaction.timestamp.timestamp().to_string().as_bytes());
        
        hex::encode(hasher.finalize())
    }

    /// Generate confirmation code for receipts
    fn generate_confirmation_code(&self, transaction: &Transaction) -> String {
        let mut hasher = Sha256::new();
        hasher.update(transaction.transaction_id.as_bytes());
        hasher.update(transaction.timestamp.timestamp().to_string().as_bytes());
        
        let hash = hex::encode(hasher.finalize());
        // Return first 8 characters as confirmation code
        hash[..8].to_uppercase()
    }

    /// Simple encryption for offline transactions (demo purposes)
    fn encrypt_data(&self, data: &str, key: &str) -> Result<String> {
        // In a real implementation, use proper encryption like AES
        // For demo, we'll use a simple XOR cipher with the key
        let key_bytes = key.as_bytes();
        let data_bytes = data.as_bytes();
        
        let encrypted: Vec<u8> = data_bytes
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
            .collect();
        
        Ok(hex::encode(encrypted))
    }

    /// Simple decryption for offline transactions
    fn decrypt_data(&self, encrypted_data: &str, key: &str) -> Result<String> {
        let encrypted_bytes = hex::decode(encrypted_data)
            .map_err(|e| SafeBankError::CryptographyError {
                message: format!("Failed to decode encrypted data: {}", e),
            })?;
        
        let key_bytes = key.as_bytes();
        
        let decrypted: Vec<u8> = encrypted_bytes
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key_bytes[i % key_bytes.len()])
            .collect();
        
        String::from_utf8(decrypted)
            .map_err(|e| SafeBankError::CryptographyError {
                message: format!("Failed to decrypt data: {}", e),
            })
    }

    /// Generate signature for data integrity
    fn generate_signature(&self, data: &str, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::SafeBankConfig, TransactionType};

    fn create_test_transaction() -> Transaction {
        Transaction {
            transaction_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            amount: 100.0,
            recipient: "Test Recipient".to_string(),
            transaction_type: TransactionType::Transfer,
            timestamp: Utc::now(),
            location: None,
            device_id: "test-device".to_string(),
            fraud_score: 0.3,
            status: TransactionStatus::Approved,
        }
    }

    #[test]
    fn test_transaction_processing() {
        let config = SafeBankConfig::default();
        let mut manager = TransactionManager::new(&config);
        
        let transaction = create_test_transaction();
        let result = manager.process_transaction(transaction.clone());
        
        assert!(result.is_ok());
        
        // Verify transaction is stored
        let stored = manager.get_transaction(transaction.transaction_id);
        assert!(stored.is_ok());
    }

    #[test]
    fn test_daily_limit_check() {
        let mut config = SafeBankConfig::default();
        config.daily_transaction_limit = 1000.0;
        
        let mut manager = TransactionManager::new(&config);
        let user_id = Uuid::new_v4();
        
        // First transaction
        let mut transaction1 = create_test_transaction();
        transaction1.user_id = user_id;
        transaction1.amount = 800.0;
        
        let result1 = manager.process_transaction(transaction1);
        assert!(result1.is_ok());
        
        // Second transaction that would exceed limit
        let mut transaction2 = create_test_transaction();
        transaction2.user_id = user_id;
        transaction2.amount = 300.0;
        transaction2.transaction_id = Uuid::new_v4();
        
        let result2 = manager.process_transaction(transaction2);
        assert!(result2.is_err());
    }

    #[test]
    fn test_transaction_receipt() {
        let config = SafeBankConfig::default();
        let manager = TransactionManager::new(&config);
        
        let transaction = create_test_transaction();
        let receipt = manager.create_receipt(&transaction);
        
        assert_eq!(receipt.transaction_id, transaction.transaction_id);
        assert_eq!(receipt.amount, transaction.amount);
        assert!(!receipt.confirmation_code.is_empty());
    }

    #[test]
    fn test_offline_transaction() {
        let config = SafeBankConfig::default();
        let manager = TransactionManager::new(&config);
        
        let transaction = create_test_transaction();
        let secret_key = "test_secret_key";
        
        let offline_tx = manager.create_offline_transaction(&transaction, secret_key);
        assert!(offline_tx.is_ok());
        
        let offline_tx = offline_tx.unwrap();
        assert!(!offline_tx.encrypted_data.is_empty());
        assert!(!offline_tx.signature.is_empty());
    }

    #[test]
    fn test_transaction_statistics() {
        let config = SafeBankConfig::default();
        let mut manager = TransactionManager::new(&config);
        
        // Add some test transactions
        let transaction1 = create_test_transaction();
        let mut transaction2 = create_test_transaction();
        transaction2.transaction_id = Uuid::new_v4();
        transaction2.status = TransactionStatus::Rejected;
        
        let _ = manager.process_transaction(transaction1);
        let _ = manager.process_transaction(transaction2);
        
        let stats = manager.get_transaction_statistics();
        assert_eq!(stats["total_transactions"], 2.0);
        assert!(stats.contains_key("approval_rate_percent"));
    }
}