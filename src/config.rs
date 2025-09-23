//! Configuration module for SafeBank framework
//! Optimized for rural banking environments with low resource constraints

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeBankConfig {
    /// Maximum allowed failed authentication attempts before lockout
    pub max_failed_attempts: u32,
    
    /// Account lockout duration in minutes
    pub lockout_duration_minutes: u32,
    
    /// Fraud detection thresholds (0.0 to 1.0)
    pub fraud_threshold_low: f64,
    pub fraud_threshold_medium: f64,
    pub fraud_threshold_high: f64,
    
    /// Transaction limits
    pub daily_transaction_limit: f64,
    pub single_transaction_limit: f64,
    
    /// Security settings
    pub require_device_verification: bool,
    pub enable_behavioral_analysis: bool,
    pub pin_complexity_required: bool,
    
    /// Offline mode settings
    pub offline_transaction_limit: f64,
    pub offline_cache_duration_hours: u32,
    
    /// Performance optimizations for low-end devices
    pub enable_lightweight_encryption: bool,
    pub cache_size_mb: u32,
    pub sync_interval_minutes: u32,
    
    /// Rural-specific settings
    pub low_connectivity_mode: bool,
    pub simplified_interface: bool,
    pub local_currency: String,
}

impl Default for SafeBankConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            fraud_threshold_low: 0.3,
            fraud_threshold_medium: 0.6,
            fraud_threshold_high: 0.8,
            daily_transaction_limit: 10000.0, // Adjust based on local currency
            single_transaction_limit: 5000.0,
            require_device_verification: true,
            enable_behavioral_analysis: true,
            pin_complexity_required: false, // Simplified for rural users
            offline_transaction_limit: 1000.0,
            offline_cache_duration_hours: 24,
            enable_lightweight_encryption: true,
            cache_size_mb: 50, // Conservative for low-end devices
            sync_interval_minutes: 30,
            low_connectivity_mode: true,
            simplified_interface: true,
            local_currency: "USD".to_string(),
        }
    }
}

impl SafeBankConfig {
    /// Create configuration optimized for very low-resource environments
    pub fn minimal() -> Self {
        Self {
            max_failed_attempts: 3,
            lockout_duration_minutes: 10,
            fraud_threshold_low: 0.4,
            fraud_threshold_medium: 0.7,
            fraud_threshold_high: 0.9,
            daily_transaction_limit: 5000.0,
            single_transaction_limit: 2000.0,
            require_device_verification: true,
            enable_behavioral_analysis: false, // Disable to save resources
            pin_complexity_required: false,
            offline_transaction_limit: 500.0,
            offline_cache_duration_hours: 12,
            enable_lightweight_encryption: true,
            cache_size_mb: 20,
            sync_interval_minutes: 60,
            low_connectivity_mode: true,
            simplified_interface: true,
            local_currency: "USD".to_string(),
        }
    }

    /// Validate configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.fraud_threshold_low >= self.fraud_threshold_medium {
            return Err("Low fraud threshold must be less than medium threshold".to_string());
        }
        
        if self.fraud_threshold_medium >= self.fraud_threshold_high {
            return Err("Medium fraud threshold must be less than high threshold".to_string());
        }
        
        if self.daily_transaction_limit < self.single_transaction_limit {
            return Err("Daily limit must be greater than or equal to single transaction limit".to_string());
        }
        
        if self.cache_size_mb == 0 {
            return Err("Cache size must be greater than 0".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = SafeBankConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_minimal_config_is_valid() {
        let config = SafeBankConfig::minimal();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_thresholds() {
        let mut config = SafeBankConfig::default();
        config.fraud_threshold_low = 0.8;
        config.fraud_threshold_medium = 0.5;
        assert!(config.validate().is_err());
    }
}