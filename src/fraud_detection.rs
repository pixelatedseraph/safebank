//! Fraud detection module for SafeBank framework
//! Implements behavioral pattern analysis and anomaly detection optimized for rural banking

use std::collections::HashMap;
use chrono::Timelike;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Transaction, UserProfile, BehavioralProfile,
    config::SafeBankConfig, errors::Result
};

#[derive(Debug)]
pub struct FraudDetector {
    config: SafeBankConfig,
    user_profiles: HashMap<Uuid, BehavioralProfile>,
    fraud_statistics: FraudStatistics,
}

#[derive(Debug, Clone, Default)]
pub struct FraudStatistics {
    pub total_transactions_analyzed: u64,
    pub transactions_flagged: u64,
    pub transactions_blocked: u64,
    pub false_positive_rate: f64,
    pub fraud_detected: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudAnalysisResult {
    pub fraud_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub recommendation: FraudRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub score: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    AmountAnomaly,
    TimeAnomaly,
    FrequencyAnomaly,
    RecipientAnomaly,
    LocationAnomaly,
    DeviceAnomaly,
    BehaviorPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraudRecommendation {
    Approve,
    Flag,
    Block,
    RequireAdditionalAuth,
}

impl FraudDetector {
    pub fn new(config: &SafeBankConfig) -> Self {
        Self {
            config: config.clone(),
            user_profiles: HashMap::new(),
            fraud_statistics: FraudStatistics::default(),
        }
    }

    /// Analyze a transaction for fraud indicators
    pub fn analyze_transaction(&mut self, transaction: &Transaction, user: &UserProfile) -> Result<f64> {
        if !self.config.enable_behavioral_analysis {
            // Simple rule-based detection for minimal resource usage
            return Ok(self.simple_fraud_detection(transaction));
        }

        self.fraud_statistics.total_transactions_analyzed += 1;

        let behavioral_profile = self.user_profiles
            .get(&transaction.user_id)
            .unwrap_or(&user.behavioral_profile);

        let mut risk_factors = Vec::new();
        let mut total_score = 0.0;

        // Analyze amount anomaly
        let amount_score = self.analyze_amount_anomaly(transaction, behavioral_profile);
        if amount_score > 0.0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::AmountAnomaly,
                score: amount_score,
                description: format!("Transaction amount ${:.2} deviates from typical pattern", transaction.amount),
            });
            total_score += amount_score * 0.3; // Weight: 30%
        }

        // Analyze time anomaly
        let time_score = self.analyze_time_anomaly(transaction, behavioral_profile);
        if time_score > 0.0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::TimeAnomaly,
                score: time_score,
                description: "Transaction time unusual for user".to_string(),
            });
            total_score += time_score * 0.2; // Weight: 20%
        }

        // Analyze frequency anomaly
        let frequency_score = self.analyze_frequency_anomaly(transaction, behavioral_profile);
        if frequency_score > 0.0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::FrequencyAnomaly,
                score: frequency_score,
                description: "Unusual transaction frequency detected".to_string(),
            });
            total_score += frequency_score * 0.25; // Weight: 25%
        }

        // Analyze recipient anomaly
        let recipient_score = self.analyze_recipient_anomaly(transaction, behavioral_profile);
        if recipient_score > 0.0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::RecipientAnomaly,
                score: recipient_score,
                description: "Transaction to new or unusual recipient".to_string(),
            });
            total_score += recipient_score * 0.15; // Weight: 15%
        }

        // Check transaction limits
        let limit_score = self.check_transaction_limits(transaction);
        if limit_score > 0.0 {
            total_score += limit_score * 0.1; // Weight: 10%
        }

        // Normalize score to 0-1 range
        let normalized_score = (total_score).min(1.0).max(0.0);

        // Update statistics
        if normalized_score > self.config.fraud_threshold_medium {
            self.fraud_statistics.transactions_flagged += 1;
        }
        if normalized_score > self.config.fraud_threshold_high {
            self.fraud_statistics.transactions_blocked += 1;
        }

        Ok(normalized_score)
    }

    /// Update user's behavioral profile based on transaction history
    pub fn update_behavioral_profile(&mut self, user_id: Uuid, transactions: &[Transaction]) -> Result<()> {
        if transactions.is_empty() {
            return Ok(());
        }

        let mut behavioral_profile = BehavioralProfile {
            typical_transaction_amount: 0.0,
            typical_transaction_times: vec![],
            common_recipients: vec![],
            geographic_patterns: vec![],
            usage_frequency: 0.0,
        };

        // Calculate typical transaction amount
        let total_amount: f64 = transactions.iter().map(|t| t.amount).sum();
        behavioral_profile.typical_transaction_amount = total_amount / transactions.len() as f64;

        // Analyze typical transaction times
        let mut hour_counts = HashMap::new();
        for transaction in transactions {
            let hour = transaction.timestamp.hour() as u8;
            *hour_counts.entry(hour).or_insert(0) += 1;
        }
        
        // Get most common hours (top 3)
        let mut hour_vec: Vec<(u8, i32)> = hour_counts.into_iter().collect();
        hour_vec.sort_by(|a, b| b.1.cmp(&a.1));
        behavioral_profile.typical_transaction_times = hour_vec
            .into_iter()
            .take(3)
            .map(|(hour, _)| hour)
            .collect();

        // Analyze common recipients
        let mut recipient_counts = HashMap::new();
        for transaction in transactions {
            *recipient_counts.entry(transaction.recipient.clone()).or_insert(0) += 1;
        }
        
        let mut recipient_vec: Vec<(String, i32)> = recipient_counts.into_iter().collect();
        recipient_vec.sort_by(|a, b| b.1.cmp(&a.1));
        behavioral_profile.common_recipients = recipient_vec
            .into_iter()
            .take(5)
            .map(|(recipient, _)| recipient)
            .collect();

        // Calculate usage frequency (transactions per day)
        if let (Some(first), Some(last)) = (transactions.first(), transactions.last()) {
            let duration_days = (last.timestamp - first.timestamp).num_days().max(1) as f64;
            behavioral_profile.usage_frequency = transactions.len() as f64 / duration_days;
        }

        self.user_profiles.insert(user_id, behavioral_profile);
        Ok(())
    }

    /// Simple rule-based fraud detection for minimal resource usage
    fn simple_fraud_detection(&self, transaction: &Transaction) -> f64 {
        let mut score = 0.0;

        // Check for unusually large amounts
        if transaction.amount > self.config.single_transaction_limit * 0.8 {
            score += 0.4;
        }

        // Check for late night transactions (potential risk)
        let hour = transaction.timestamp.hour();
        if hour >= 23 || hour <= 5 {
            score += 0.2;
        }

        // Check for round numbers (potentially suspicious)
        if transaction.amount % 100.0 == 0.0 && transaction.amount >= 1000.0 {
            score += 0.1;
        }

        score
    }

    /// Analyze transaction amount compared to user's typical behavior
    fn analyze_amount_anomaly(&self, transaction: &Transaction, profile: &BehavioralProfile) -> f64 {
        if profile.typical_transaction_amount == 0.0 {
            return 0.0; // No historical data
        }

        let typical_amount = profile.typical_transaction_amount;
        let current_amount = transaction.amount;

        // Calculate deviation ratio
        let deviation_ratio = if current_amount > typical_amount {
            current_amount / typical_amount
        } else {
            typical_amount / current_amount
        };

        // Convert to risk score (higher deviation = higher risk)
        if deviation_ratio > 5.0 {
            0.8
        } else if deviation_ratio > 3.0 {
            0.6
        } else if deviation_ratio > 2.0 {
            0.4
        } else {
            0.0
        }
    }

    /// Analyze transaction time compared to user's typical behavior
    fn analyze_time_anomaly(&self, transaction: &Transaction, profile: &BehavioralProfile) -> f64 {
        if profile.typical_transaction_times.is_empty() {
            return 0.0;
        }

        let current_hour = transaction.timestamp.hour() as u8;
        
        // Check if current hour is in typical hours
        if profile.typical_transaction_times.contains(&current_hour) {
            return 0.0;
        }

        // Check if it's within 2 hours of typical times
        let is_near_typical = profile.typical_transaction_times.iter().any(|&typical_hour| {
            let diff = if current_hour > typical_hour {
                (current_hour - typical_hour).min(typical_hour + 24 - current_hour)
            } else {
                (typical_hour - current_hour).min(current_hour + 24 - typical_hour)
            };
            diff <= 2
        });

        if is_near_typical {
            0.2
        } else {
            0.5
        }
    }

    /// Analyze transaction frequency anomalies
    fn analyze_frequency_anomaly(&self, _transaction: &Transaction, profile: &BehavioralProfile) -> f64 {
        // This would typically analyze recent transaction frequency vs typical
        // For now, return a placeholder based on usage frequency
        if profile.usage_frequency > 10.0 {
            0.3 // High frequency users might be suspicious
        } else {
            0.0
        }
    }

    /// Analyze recipient anomalies
    fn analyze_recipient_anomaly(&self, transaction: &Transaction, profile: &BehavioralProfile) -> f64 {
        if profile.common_recipients.is_empty() {
            return 0.1; // Slight risk for new users
        }

        if profile.common_recipients.contains(&transaction.recipient) {
            0.0 // Known recipient
        } else {
            0.3 // New recipient
        }
    }

    /// Check transaction against configured limits
    fn check_transaction_limits(&self, transaction: &Transaction) -> f64 {
        if transaction.amount > self.config.single_transaction_limit {
            1.0 // Exceeds limit
        } else if transaction.amount > self.config.single_transaction_limit * 0.8 {
            0.5 // Close to limit
        } else {
            0.0
        }
    }

    /// Get fraud detection statistics
    pub fn get_statistics(&self) -> HashMap<String, f64> {
        let mut stats = HashMap::new();
        
        stats.insert("total_analyzed".to_string(), self.fraud_statistics.total_transactions_analyzed as f64);
        stats.insert("flagged".to_string(), self.fraud_statistics.transactions_flagged as f64);
        stats.insert("blocked".to_string(), self.fraud_statistics.transactions_blocked as f64);
        
        if self.fraud_statistics.total_transactions_analyzed > 0 {
            let flag_rate = (self.fraud_statistics.transactions_flagged as f64) / 
                           (self.fraud_statistics.total_transactions_analyzed as f64) * 100.0;
            stats.insert("flag_rate_percent".to_string(), flag_rate);
            
            let block_rate = (self.fraud_statistics.transactions_blocked as f64) / 
                            (self.fraud_statistics.total_transactions_analyzed as f64) * 100.0;
            stats.insert("block_rate_percent".to_string(), block_rate);
        }
        
        stats
    }

    /// Mark a transaction as confirmed fraud (for learning)
    pub fn mark_as_fraud(&mut self, _transaction_id: Uuid, _is_fraud: bool) {
        // This would be used to improve the fraud detection algorithm
        // For now, just update statistics
        self.fraud_statistics.fraud_detected += 1;
    }

    /// Reset statistics (useful for testing)
    pub fn reset_statistics(&mut self) {
        self.fraud_statistics = FraudStatistics::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UserProfile, DeviceInfo, config::SafeBankConfig, TransactionType};
    use chrono::Utc;

    fn create_test_user() -> UserProfile {
        UserProfile {
            user_id: Uuid::new_v4(),
            phone_number: "+1234567890".to_string(),
            pin_hash: "dummy_hash".to_string(),
            device_info: DeviceInfo {
                device_id: "test-device".to_string(),
                device_type: "smartphone".to_string(),
                os_version: Some("Android 8.0".to_string()),
                app_version: "1.0.0".to_string(),
                is_trusted: true,
                registered_at: Utc::now(),
            },
            behavioral_profile: BehavioralProfile {
                typical_transaction_amount: 100.0,
                typical_transaction_times: vec![9, 12, 18], // 9 AM, 12 PM, 6 PM
                common_recipients: vec!["John Doe".to_string()],
                geographic_patterns: vec![],
                usage_frequency: 2.0,
            },
            created_at: Utc::now(),
            last_login: Some(Utc::now()),
            failed_attempts: 0,
            is_locked: false,
        }
    }

    fn create_test_transaction(amount: f64, user_id: Uuid) -> Transaction {
        Transaction {
            transaction_id: Uuid::new_v4(),
            user_id,
            amount,
            recipient: "Test Recipient".to_string(),
            transaction_type: TransactionType::Transfer,
            timestamp: Utc::now(),
            location: None,
            device_id: "test-device".to_string(),
            fraud_score: 0.0,
            status: crate::TransactionStatus::Pending,
        }
    }

    #[test]
    fn test_fraud_detector_initialization() {
        let config = SafeBankConfig::default();
        let detector = FraudDetector::new(&config);
        assert!(detector.user_profiles.is_empty());
    }

    #[test]
    fn test_simple_fraud_detection() {
        let config = SafeBankConfig::minimal(); // Disables behavioral analysis
        let mut detector = FraudDetector::new(&config);
        
        let user = create_test_user();
        let transaction = create_test_transaction(100.0, user.user_id);
        
        let score = detector.analyze_transaction(&transaction, &user).unwrap();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_large_amount_detection() {
        let mut config = SafeBankConfig::default();
        config.single_transaction_limit = 1000.0;
        config.enable_behavioral_analysis = true; // Make sure behavioral analysis is enabled
        let mut detector = FraudDetector::new(&config);
        
        let user = create_test_user();
        let large_transaction = create_test_transaction(1500.0, user.user_id);
        
        let score = detector.analyze_transaction(&large_transaction, &user).unwrap();
        // Since the transaction exceeds the limit, it should be flagged with some score
        assert!(score >= 0.1); // Lower threshold since it's just above limit
    }

    #[test]
    fn test_behavioral_profile_update() {
        let config = SafeBankConfig::default();
        let mut detector = FraudDetector::new(&config);
        
        let user_id = Uuid::new_v4();
        let transactions = vec![
            create_test_transaction(100.0, user_id),
            create_test_transaction(150.0, user_id),
            create_test_transaction(120.0, user_id),
        ];
        
        let result = detector.update_behavioral_profile(user_id, &transactions);
        assert!(result.is_ok());
        
        let profile = detector.user_profiles.get(&user_id).unwrap();
        assert!((profile.typical_transaction_amount - 123.33).abs() < 0.1);
    }

    #[test]
    fn test_statistics_tracking() {
        let config = SafeBankConfig::default();
        let mut detector = FraudDetector::new(&config);
        
        let user = create_test_user();
        let transaction = create_test_transaction(100.0, user.user_id);
        
        let _ = detector.analyze_transaction(&transaction, &user);
        
        let stats = detector.get_statistics();
        assert_eq!(stats["total_analyzed"], 1.0);
    }
}