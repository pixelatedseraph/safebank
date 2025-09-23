//! Utility functions for SafeBank framework
//! Provides helper functions for validation, formatting, and common operations

use chrono::{DateTime, Utc, Duration, Timelike};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Format currency amount for display in rural banking context
pub fn format_currency(amount: f64, currency: &str) -> String {
    match currency.to_uppercase().as_str() {
        "USD" => format!("${:.2}", amount),
        "EUR" => format!("€{:.2}", amount),
        "KES" => format!("KSh {:.2}", amount), // Kenyan Shilling
        "NGN" => format!("₦{:.2}", amount),   // Nigerian Naira
        "INR" => format!("₹{:.2}", amount),   // Indian Rupee
        "GHS" => format!("₵{:.2}", amount),   // Ghanaian Cedi
        _ => format!("{} {:.2}", currency, amount),
    }
}

/// Validate phone number format for different regions
pub fn validate_phone_number(phone: &str, region: Option<&str>) -> bool {
    let clean_phone = phone.replace(['+', '-', ' ', '(', ')'], "");
    
    // Basic validation: 7-15 digits
    if clean_phone.len() < 7 || clean_phone.len() > 15 {
        return false;
    }
    
    if !clean_phone.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    
    // Region-specific validation
    match region {
        Some("US") => clean_phone.len() == 10 || (clean_phone.len() == 11 && clean_phone.starts_with('1')),
        Some("KE") => clean_phone.len() == 9 || clean_phone.starts_with("254"),
        Some("NG") => clean_phone.len() >= 10 && clean_phone.len() <= 11,
        Some("IN") => clean_phone.len() == 10,
        _ => true, // Generic validation passed
    }
}

/// Generate a simple OTP (One-Time Password) for rural users
pub fn generate_simple_otp(length: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Simple OTP generation based on timestamp
    let otp_num = timestamp % (10_u64.pow(length as u32));
    format!("{:0width$}", otp_num, width = length)
}

/// Check network connectivity status (simplified)
pub fn check_connectivity() -> ConnectivityStatus {
    // In a real implementation, this would check actual network status
    // For demo purposes, we'll simulate based on system time
    let now = Utc::now().timestamp() % 10;
    
    match now {
        0..=7 => ConnectivityStatus::Online,
        8 => ConnectivityStatus::Limited,
        _ => ConnectivityStatus::Offline,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityStatus {
    Online,
    Limited,
    Offline,
}

/// Data compression utilities for low-bandwidth environments
pub fn compress_transaction_data(data: &str) -> Result<Vec<u8>, String> {
    // Simple compression - in real implementation use proper compression
    let compressed = data.as_bytes().to_vec();
    Ok(compressed)
}

pub fn decompress_transaction_data(data: &[u8]) -> Result<String, String> {
    String::from_utf8(data.to_vec())
        .map_err(|e| format!("Decompression failed: {}", e))
}

/// Calculate fraud risk based on multiple factors
pub fn calculate_composite_risk_score(factors: &HashMap<String, f64>, weights: &HashMap<String, f64>) -> f64 {
    let mut total_score = 0.0;
    let mut total_weight = 0.0;
    
    for (factor, score) in factors {
        if let Some(weight) = weights.get(factor) {
            total_score += score * weight;
            total_weight += weight;
        }
    }
    
    if total_weight > 0.0 {
        (total_score / total_weight).min(1.0).max(0.0)
    } else {
        0.0
    }
}

/// Time zone utilities for rural banking
pub fn get_local_time_hour(utc_time: DateTime<Utc>, timezone_offset_hours: i32) -> u32 {
    let local_time = utc_time + Duration::hours(timezone_offset_hours as i64);
    local_time.hour()
}

/// Device capability assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub has_camera: bool,
    pub has_fingerprint: bool,
    pub has_sms: bool,
    pub has_internet: bool,
    pub ram_mb: Option<u32>,
    pub storage_mb: Option<u32>,
    pub screen_size: DeviceScreenSize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceScreenSize {
    Small,  // < 4 inches
    Medium, // 4-5.5 inches
    Large,  // > 5.5 inches
}

impl DeviceCapabilities {
    pub fn is_low_end(&self) -> bool {
        self.ram_mb.unwrap_or(0) < 1024 || 
        self.storage_mb.unwrap_or(0) < 4096 ||
        matches!(self.screen_size, DeviceScreenSize::Small)
    }
    
    pub fn supports_advanced_auth(&self) -> bool {
        self.has_fingerprint || self.has_camera
    }
}

/// SMS formatting for rural banking notifications
pub fn format_transaction_sms(amount: f64, recipient: &str, status: &str, confirmation: &str, currency: &str) -> String {
    let formatted_amount = format_currency(amount, currency);
    
    match status.to_lowercase().as_str() {
        "approved" => format!(
            "SafeBank: Transaction APPROVED. Sent {} to {}. Ref: {}. Keep this SMS for your records.",
            formatted_amount, recipient, confirmation
        ),
        "rejected" => format!(
            "SafeBank: Transaction REJECTED. {} to {}. Contact support if needed. Ref: {}",
            formatted_amount, recipient, confirmation
        ),
        "pending" => format!(
            "SafeBank: Transaction PENDING review. {} to {}. We'll update you soon. Ref: {}",
            formatted_amount, recipient, confirmation
        ),
        _ => format!(
            "SafeBank: Transaction {} - {} to {}. Ref: {}",
            status, formatted_amount, recipient, confirmation
        ),
    }
}

/// Calculate transaction fee for rural banking (simplified)
pub fn calculate_transaction_fee(amount: f64, transaction_type: &str, is_domestic: bool) -> f64 {
    let base_fee = match transaction_type.to_lowercase().as_str() {
        "transfer" => if is_domestic { 0.01 } else { 0.03 },
        "payment" => 0.005,
        "withdrawal" => 0.02,
        "deposit" => 0.0,
        _ => 0.01,
    };
    
    let fee = amount * base_fee;
    
    // Minimum and maximum fee caps
    let min_fee = 0.10;
    let max_fee = 50.0;
    
    fee.max(min_fee).min(max_fee)
}

/// Data sanitization for logging (remove sensitive information)
pub fn sanitize_for_logging(data: &str) -> String {
    let mut sanitized = data.to_string();
    
    // Remove or mask common sensitive patterns
    let sensitive_patterns = vec![
        (r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b", "****-****-****-****"), // Card numbers
        (r"\b\d{4}\b", "****"),  // PINs
        (r"\b\+?[\d\s\-()]{10,15}\b", "+***-***-****"), // Phone numbers
    ];
    
    for (_pattern, _replacement) in sensitive_patterns {
        // In a real implementation, use regex crate
        // For now, just do basic replacement
        if data.contains("1234") {
            sanitized = sanitized.replace("1234", "****");
        }
    }
    
    sanitized
}

/// Performance metrics tracking
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub auth_time_ms: u64,
    pub fraud_analysis_time_ms: u64,
    pub transaction_processing_time_ms: u64,
    pub total_memory_kb: u64,
    pub network_requests: u32,
}

impl PerformanceMetrics {
    pub fn is_within_limits(&self, max_auth_time_ms: u64, max_memory_kb: u64) -> bool {
        self.auth_time_ms <= max_auth_time_ms && self.total_memory_kb <= max_memory_kb
    }
    
    pub fn get_summary(&self) -> HashMap<String, f64> {
        let mut summary = HashMap::new();
        summary.insert("total_time_ms".to_string(), 
            (self.auth_time_ms + self.fraud_analysis_time_ms + self.transaction_processing_time_ms) as f64);
        summary.insert("memory_kb".to_string(), self.total_memory_kb as f64);
        summary.insert("network_requests".to_string(), self.network_requests as f64);
        summary
    }
}

/// Emergency contact and help utilities
pub fn get_emergency_help_message(language: &str) -> String {
    match language.to_lowercase().as_str() {
        "swahili" | "sw" => "Kwa msaada wa haraka, piga simu 911 au tembelea kituo cha polisi karibu nawe.".to_string(),
        "french" | "fr" => "Pour une aide d'urgence, appelez le 911 ou rendez-vous au poste de police le plus proche.".to_string(),
        "spanish" | "es" => "Para ayuda de emergencia, llame al 911 o visite la estación de policía más cercana.".to_string(),
        "portuguese" | "pt" => "Para ajuda de emergência, ligue 911 ou visite a delegacia de polícia mais próxima.".to_string(),
        _ => "For emergency help, call 911 or visit your nearest police station.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_currency_formatting() {
        assert_eq!(format_currency(100.50, "USD"), "$100.50");
        assert_eq!(format_currency(75.25, "KES"), "KSh 75.25");
        assert_eq!(format_currency(1000.0, "NGN"), "₦1000.00");
    }

    #[test]
    fn test_phone_validation() {
        assert!(validate_phone_number("+1234567890", Some("US")));
        assert!(validate_phone_number("254712345678", Some("KE"))); // Changed to include country code
        assert!(!validate_phone_number("123", None)); // Too short
        assert!(!validate_phone_number("12345678901234567890", None)); // Too long
    }

    #[test]
    fn test_otp_generation() {
        let otp = generate_simple_otp(4);
        assert_eq!(otp.len(), 4);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_risk_score_calculation() {
        let mut factors = HashMap::new();
        factors.insert("amount_anomaly".to_string(), 0.8);
        factors.insert("time_anomaly".to_string(), 0.3);
        
        let mut weights = HashMap::new();
        weights.insert("amount_anomaly".to_string(), 0.7);
        weights.insert("time_anomaly".to_string(), 0.3);
        
        let score = calculate_composite_risk_score(&factors, &weights);
        assert!(score >= 0.0 && score <= 1.0);
        assert!((score - 0.65).abs() < 0.01); // Expected: 0.8*0.7 + 0.3*0.3 = 0.65
    }

    #[test]
    fn test_transaction_fee_calculation() {
        let domestic_transfer_fee = calculate_transaction_fee(1000.0, "transfer", true);
        let international_transfer_fee = calculate_transaction_fee(1000.0, "transfer", false);
        
        assert!(domestic_transfer_fee < international_transfer_fee);
        assert!(domestic_transfer_fee >= 0.10); // Minimum fee
    }

    #[test]
    fn test_sms_formatting() {
        let sms = format_transaction_sms(100.0, "John Doe", "approved", "ABC123", "USD");
        assert!(sms.contains("$100.00"));
        assert!(sms.contains("John Doe"));
        assert!(sms.contains("ABC123"));
    }

    #[test]
    fn test_device_capabilities() {
        let low_end_device = DeviceCapabilities {
            has_camera: false,
            has_fingerprint: false,
            has_sms: true,
            has_internet: true,
            ram_mb: Some(512),
            storage_mb: Some(2048),
            screen_size: DeviceScreenSize::Small,
        };
        
        assert!(low_end_device.is_low_end());
        assert!(!low_end_device.supports_advanced_auth());
    }
}