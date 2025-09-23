//! Error handling for SafeBank framework

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SafeBankError {
    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },
    
    #[error("Account locked due to too many failed attempts")]
    AccountLocked,
    
    #[error("User not found: {user_id}")]
    UserNotFound { user_id: String },
    
    #[error("Invalid PIN format")]
    InvalidPin,
    
    #[error("Device not recognized: {device_id}")]
    UnrecognizedDevice { device_id: String },
    
    #[error("Transaction rejected by fraud detection: score {fraud_score}")]
    FraudDetected { fraud_score: f64 },
    
    #[error("Transaction limit exceeded: {amount} > {limit}")]
    TransactionLimitExceeded { amount: f64, limit: f64 },
    
    #[error("Insufficient funds: balance {balance}, required {required}")]
    InsufficientFunds { balance: f64, required: f64 },
    
    #[error("Network connectivity issue: {message}")]
    NetworkError { message: String },
    
    #[error("Data serialization error: {message}")]
    SerializationError { message: String },
    
    #[error("Configuration error: {message}")]
    ConfigError { message: String },
    
    #[error("Encryption/Decryption error: {message}")]
    CryptographyError { message: String },
    
    #[error("Storage error: {message}")]
    StorageError { message: String },
    
    #[error("Resource limit exceeded: {resource}")]
    ResourceLimitExceeded { resource: String },
    
    #[error("Operation not supported in offline mode")]
    OfflineModeRestriction,
    
    #[error("Timeout occurred during operation: {operation}")]
    TimeoutError { operation: String },
    
    #[error("Invalid transaction state: {current_state}")]
    InvalidTransactionState { current_state: String },
}

impl SafeBankError {
    /// Convert error to user-friendly message appropriate for rural banking context
    pub fn to_user_message(&self) -> String {
        match self {
            SafeBankError::AuthenticationFailed { .. } => {
                "Invalid phone number or PIN. Please try again.".to_string()
            }
            SafeBankError::AccountLocked => {
                "Account temporarily locked for security. Please try again later.".to_string()
            }
            SafeBankError::InvalidPin => {
                "PIN must be 4-6 digits. Please enter a valid PIN.".to_string()
            }
            SafeBankError::FraudDetected { .. } => {
                "Transaction flagged for security review. Please contact support.".to_string()
            }
            SafeBankError::TransactionLimitExceeded { limit, .. } => {
                format!("Transaction exceeds daily limit of ${:.2}", limit)
            }
            SafeBankError::InsufficientFunds { balance, .. } => {
                format!("Insufficient balance. Available: ${:.2}", balance)
            }
            SafeBankError::NetworkError { .. } => {
                "Network connection issue. Please check your connection and try again.".to_string()
            }
            SafeBankError::OfflineModeRestriction => {
                "This operation requires internet connection.".to_string()
            }
            SafeBankError::TimeoutError { .. } => {
                "Operation timed out. Please try again.".to_string()
            }
            _ => "An error occurred. Please try again or contact support.".to_string(),
        }
    }

    /// Check if error is recoverable (user can retry)
    pub fn is_recoverable(&self) -> bool {
        match self {
            SafeBankError::NetworkError { .. } 
            | SafeBankError::TimeoutError { .. }
            | SafeBankError::AuthenticationFailed { .. } => true,
            
            SafeBankError::AccountLocked 
            | SafeBankError::FraudDetected { .. }
            | SafeBankError::TransactionLimitExceeded { .. }
            | SafeBankError::InsufficientFunds { .. } => false,
            
            _ => false,
        }
    }

    /// Get severity level for logging
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            SafeBankError::FraudDetected { .. } 
            | SafeBankError::CryptographyError { .. } => ErrorSeverity::Critical,
            
            SafeBankError::AccountLocked 
            | SafeBankError::TransactionLimitExceeded { .. }
            | SafeBankError::InsufficientFunds { .. } => ErrorSeverity::High,
            
            SafeBankError::AuthenticationFailed { .. }
            | SafeBankError::NetworkError { .. } => ErrorSeverity::Medium,
            
            _ => ErrorSeverity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

// Convenience type alias
pub type Result<T> = std::result::Result<T, SafeBankError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_user_messages() {
        let error = SafeBankError::InvalidPin;
        assert!(error.to_user_message().contains("PIN must be"));
        
        let error = SafeBankError::AccountLocked;
        assert!(!error.is_recoverable());
        
        let error = SafeBankError::NetworkError { message: "timeout".to_string() };
        assert!(error.is_recoverable());
    }

    #[test]
    fn test_error_severity() {
        let fraud_error = SafeBankError::FraudDetected { fraud_score: 0.9 };
        assert_eq!(fraud_error.severity(), ErrorSeverity::Critical);
        
        let auth_error = SafeBankError::AuthenticationFailed { message: "test".to_string() };
        assert_eq!(auth_error.severity(), ErrorSeverity::Medium);
    }
}