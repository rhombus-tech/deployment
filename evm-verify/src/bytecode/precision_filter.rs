use crate::bytecode::security::{SecurityWarning, SecurityWarningKind};
use crate::bytecode::analyzer::BytecodeAnalyzer;

/// Filters vulnerabilities to reduce false positives and support smaller projects
/// Focus on HIGH-CONFIDENCE vulnerabilities that are likely real
pub struct PrecisionFilter {
    /// Only flag vulnerabilities with confidence above this threshold
    pub confidence_threshold: f64,
    /// Known safe patterns to ignore
    pub safe_patterns: Vec<String>,
}

impl PrecisionFilter {
    pub fn new_startup_friendly() -> Self {
        Self {
            confidence_threshold: 0.75, // 75% confidence required
            safe_patterns: vec![
                "OpenZeppelin".to_string(),
                "SafeMath".to_string(),
                "ReentrancyGuard".to_string(),
                "Ownable".to_string(),
            ],
        }
    }

    pub fn new_conservative() -> Self {
        Self {
            confidence_threshold: 0.50, // 50% confidence required
            safe_patterns: vec![],
        }
    }

    /// Filter warnings to only include high-confidence vulnerabilities
    pub fn filter_warnings(&self, warnings: Vec<SecurityWarning>) -> Vec<SecurityWarning> {
        warnings
            .into_iter()
            .filter(|warning| self.is_high_confidence_vulnerability(warning))
            .collect()
    }

    /// Filter vulnerabilities to only include high-confidence ones
    pub fn filter_vulnerabilities(&self, vulnerabilities: Vec<crate::api::Vulnerability>) -> Vec<crate::api::Vulnerability> {
        vulnerabilities
            .into_iter()
            .filter(|vuln| self.is_high_confidence_vuln(vuln))
            .collect()
    }

    /// Check if a Vulnerability (API type) is high confidence
    fn is_high_confidence_vuln(&self, vuln: &crate::api::Vulnerability) -> bool {
        match vuln.vulnerability_type {
            crate::api::VulnerabilityType::Reentrancy => {
                vuln.description.contains("real reentrancy vulnerability") ||
                (vuln.description.contains("risk score:") && 
                 self.extract_confidence_score(&vuln.description) > self.confidence_threshold)
            }
            crate::api::VulnerabilityType::IntegerOverflow => {
                vuln.description.contains("arithmetic") || 
                vuln.description.contains("calculation") ||
                vuln.description.contains("multiplication")
            }
            crate::api::VulnerabilityType::IntegerUnderflow => {
                vuln.description.contains("underflow") || 
                vuln.description.contains("subtraction")
            }
            crate::api::VulnerabilityType::UncheckedCall => {
                vuln.description.contains("value") || 
                vuln.description.contains("ETH") ||
                vuln.description.contains("transfer")
            }
            crate::api::VulnerabilityType::AccessControl => {
                vuln.description.contains("SELFDESTRUCT") ||
                vuln.description.contains("DELEGATECALL") ||
                (vuln.description.contains("sensitive operation") && 
                 !self.has_safe_patterns(&vuln.description))
            }
            crate::api::VulnerabilityType::SelfDestruct => true, // Always high confidence
            crate::api::VulnerabilityType::DelegateCall => {
                vuln.description.contains("user-controlled") ||
                vuln.description.contains("unchecked")
            }
            _ => false, // Conservative: skip other types
        }
    }

    /// Determine if a vulnerability is high-confidence (likely real)
    fn is_high_confidence_vulnerability(&self, warning: &SecurityWarning) -> bool {
        // Focus on vulnerabilities that are hard to false-positive
        match warning.kind {
            SecurityWarningKind::Reentrancy => self.is_high_confidence_reentrancy(warning),
            SecurityWarningKind::ReadOnlyReentrancy => self.is_high_confidence_reentrancy(warning),
            SecurityWarningKind::CrossFunctionReentrancy => self.is_high_confidence_reentrancy(warning),
            SecurityWarningKind::CrossContractReentrancy => self.is_high_confidence_reentrancy(warning),
            SecurityWarningKind::AccessControlVulnerability => self.is_high_confidence_access_control(warning),
            SecurityWarningKind::WeakAccessControl => self.is_high_confidence_access_control(warning),
            SecurityWarningKind::IntegerOverflow => self.is_high_confidence_overflow(warning),
            SecurityWarningKind::IntegerUnderflow => self.is_high_confidence_overflow(warning), // Use same logic as overflow
            SecurityWarningKind::UncheckedExternalCall => self.is_high_confidence_unchecked_call(warning),
            SecurityWarningKind::UncheckedCallReturn => self.is_high_confidence_unchecked_call(warning),
            SecurityWarningKind::UnprotectedSelfDestruct => true, // Always high confidence
            SecurityWarningKind::UnprotectedDelegateCall => true, // Always high confidence
            _ => false, // Conservative: skip other types
        }
    }

    fn is_high_confidence_reentrancy(&self, warning: &SecurityWarning) -> bool {
        // Only flag if description contains confidence score
        warning.description.contains("real reentrancy vulnerability") ||
        warning.description.contains("risk score:") && 
        self.extract_confidence_score(&warning.description) > self.confidence_threshold
    }

    fn is_high_confidence_overflow(&self, warning: &SecurityWarning) -> bool {
        // Integer overflow is often real in mathematical operations
        warning.description.contains("arithmetic") || 
        warning.description.contains("calculation") ||
        warning.description.contains("multiplication")
    }

    fn is_high_confidence_unchecked_call(&self, warning: &SecurityWarning) -> bool {
        // Only flag if it's a value transfer
        warning.description.contains("value") || 
        warning.description.contains("ETH") ||
        warning.description.contains("transfer")
    }

    fn is_high_confidence_access_control(&self, warning: &SecurityWarning) -> bool {
        // Only flag if it's a truly sensitive operation
        warning.description.contains("SELFDESTRUCT") ||
        warning.description.contains("DELEGATECALL") ||
        warning.description.contains("sensitive operation") && 
        !self.has_safe_patterns(&warning.description)
    }

    fn is_high_confidence_proxy(&self, warning: &SecurityWarning) -> bool {
        // Proxy issues are often implementation-specific
        warning.description.contains("unprotected") ||
        warning.description.contains("malicious")
    }

    fn is_high_confidence_other(&self, warning: &SecurityWarning) -> bool {
        // Very conservative for "Other" category
        warning.description.contains("critical") ||
        warning.description.contains("exploit") ||
        warning.description.contains("drain")
    }

    fn has_safe_patterns(&self, description: &str) -> bool {
        self.safe_patterns.iter().any(|pattern| description.contains(pattern))
    }

    fn extract_confidence_score(&self, description: &str) -> f64 {
        // Extract confidence score from description like "risk score: 65%"
        if let Some(start) = description.find("risk score: ") {
            let score_str = &description[start + 12..];
            if let Some(end) = score_str.find('%') {
                if let Ok(score) = score_str[..end].parse::<f64>() {
                    return score / 100.0;
                }
            }
        }
        0.0
    }
}

/// Configuration for different use cases
pub enum FilterMode {
    /// For startups and small projects - very conservative
    StartupFriendly,
    /// For established projects - moderate filtering
    Standard,
    /// For security research - minimal filtering
    Comprehensive,
}

impl FilterMode {
    pub fn get_filter(&self) -> PrecisionFilter {
        match self {
            FilterMode::StartupFriendly => PrecisionFilter::new_startup_friendly(),
            FilterMode::Standard => PrecisionFilter::new_conservative(),
            FilterMode::Comprehensive => PrecisionFilter {
                confidence_threshold: 0.0,
                safe_patterns: vec![],
            },
        }
    }
}
