/// Regulatory Compliance Checker
/// Checks for sanctions lists, KYC bypass, securities law violations
use crate::bytecode::SecuritySeverity;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct RegulatoryComplianceChecker {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ComplianceReport {
    pub violations: Vec<ComplianceViolation>,
    pub compliance_score: f64,
    pub jurisdiction_risks: HashMap<String, f64>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ComplianceViolation {
    pub violation_type: ViolationType,
    pub severity: SecuritySeverity,
    pub jurisdiction: Vec<String>,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationType {
    SanctionsListBypass,       // OFAC, UN sanctions
    KYCBypass,                  // No KYC enforcement
    AMLViolation,               // Anti-money laundering
    SecuritiesViolation,        // Unregistered securities
    PrivacyViolation,           // GDPR, data privacy
    TaxEvasion,                 // Tax reporting violations
    UnlicensedMoneyTransmit,    // Money transmission without license
    ProhibitedJurisdiction,     // Operating in prohibited jurisdiction
    DataRetention,              // Data retention requirements
    ConsumerProtection,         // Consumer protection laws
}

impl RegulatoryComplianceChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn check_compliance(&self) -> ComplianceReport {
        let mut violations = Vec::new();

        // Check sanctions compliance
        violations.extend(self.check_sanctions_compliance());
        
        // Check KYC/AML
        violations.extend(self.check_kyc_aml_compliance());
        
        // Check securities laws
        violations.extend(self.check_securities_compliance());
        
        // Check privacy compliance
        violations.extend(self.check_privacy_compliance());
        
        // Check licensing requirements
        violations.extend(self.check_licensing_requirements());

        let jurisdiction_risks = self.assess_jurisdiction_risks(&violations);
        let compliance_score = self.calculate_compliance_score(&violations);
        let recommendations = self.generate_compliance_recommendations(&violations);

        ComplianceReport {
            violations,
            compliance_score,
            jurisdiction_risks,
            recommendations,
        }
    }

    fn check_sanctions_compliance(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Check if contract has sanctions screening
        if !self.has_sanctions_screening() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::SanctionsListBypass,
                severity: SecuritySeverity::Critical,
                jurisdiction: vec!["US".to_string(), "EU".to_string(), "UN".to_string()],
                description: "No OFAC/sanctions list screening detected".to_string(),
                remediation: "Implement sanctions screening using Chainalysis, TRM Labs, or similar".to_string(),
            });
        }

        // Check for Tornado Cash interaction
        if self.interacts_with_tornado_cash() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::SanctionsListBypass,
                severity: SecuritySeverity::Critical,
                jurisdiction: vec!["US".to_string()],
                description: "Interacts with sanctioned protocol (Tornado Cash)".to_string(),
                remediation: "Remove interaction with sanctioned protocols".to_string(),
            });
        }

        violations
    }

    fn check_kyc_aml_compliance(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Check if anonymous transfers are allowed
        if self.allows_anonymous_transfers() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::KYCBypass,
                severity: SecuritySeverity::High,
                jurisdiction: vec!["US".to_string(), "EU".to_string(), "UK".to_string()],
                description: "Allows anonymous transfers without KYC".to_string(),
                remediation: "Implement KYC verification before large transfers".to_string(),
            });
        }

        // Check transaction size limits
        if !self.has_transaction_limits() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::AMLViolation,
                severity: SecuritySeverity::High,
                jurisdiction: vec!["US".to_string(), "EU".to_string()],
                description: "No transaction size limits for AML compliance".to_string(),
                remediation: "Implement transaction limits and velocity checks".to_string(),
            });
        }

        // Check for mixing/tumbling patterns
        if self.has_mixing_pattern() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::AMLViolation,
                severity: SecuritySeverity::Critical,
                jurisdiction: vec!["US".to_string(), "EU".to_string(), "Global".to_string()],
                description: "Contract implements mixing/tumbling functionality".to_string(),
                remediation: "Remove mixing functionality or obtain money transmitter license".to_string(),
            });
        }

        violations
    }

    fn check_securities_compliance(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Check if token passes Howey Test (investment contract)
        if self.is_likely_security() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::SecuritiesViolation,
                severity: SecuritySeverity::Critical,
                jurisdiction: vec!["US".to_string(), "EU".to_string()],
                description: "Token may qualify as unregistered security (Howey Test)".to_string(),
                remediation: "Register with SEC or restructure to avoid security classification".to_string(),
            });
        }

        // Check for dividend/profit-sharing
        if self.has_profit_sharing() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::SecuritiesViolation,
                severity: SecuritySeverity::High,
                jurisdiction: vec!["US".to_string()],
                description: "Profit-sharing mechanism indicates security".to_string(),
                remediation: "Remove profit-sharing or register as security".to_string(),
            });
        }

        violations
    }

    fn check_privacy_compliance(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Check GDPR compliance (right to be forgotten)
        if self.stores_personal_data() && !self.has_data_deletion() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::PrivacyViolation,
                severity: SecuritySeverity::High,
                jurisdiction: vec!["EU".to_string()],
                description: "Stores personal data without deletion capability (GDPR violation)".to_string(),
                remediation: "Implement data deletion or use off-chain storage".to_string(),
            });
        }

        violations
    }

    fn check_licensing_requirements(&self) -> Vec<ComplianceViolation> {
        let mut violations = Vec::new();

        // Check if requires money transmitter license
        if self.facilitates_value_transfer() && !self.has_licensing_info() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::UnlicensedMoneyTransmit,
                severity: SecuritySeverity::Critical,
                jurisdiction: vec!["US".to_string(), "EU".to_string()],
                description: "Facilitates money transmission without licenses".to_string(),
                remediation: "Obtain state money transmitter licenses or use licensed partner".to_string(),
            });
        }

        violations
    }

    fn assess_jurisdiction_risks(&self, violations: &[ComplianceViolation]) -> HashMap<String, f64> {
        let mut risks: HashMap<String, f64> = HashMap::new();

        for violation in violations {
            for jurisdiction in &violation.jurisdiction {
                let risk_value = match violation.severity {
                    SecuritySeverity::Critical => 10.0,
                    SecuritySeverity::High => 7.0,
                    SecuritySeverity::Medium => 4.0,
                    SecuritySeverity::Low => 2.0,
                    SecuritySeverity::Info => 1.0,
                };
                *risks.entry(jurisdiction.clone()).or_insert(0.0) += risk_value;
            }
        }

        risks
    }

    fn calculate_compliance_score(&self, violations: &[ComplianceViolation]) -> f64 {
        if violations.is_empty() {
            return 100.0;
        }

        let penalty: f64 = violations.iter()
            .map(|v| match v.severity {
                SecuritySeverity::Critical => 25.0,
                SecuritySeverity::High => 15.0,
                SecuritySeverity::Medium => 8.0,
                SecuritySeverity::Low => 3.0,
                SecuritySeverity::Info => 1.0,
            })
            .sum();

        (100.0 - penalty).max(0.0)
    }

    fn generate_compliance_recommendations(&self, violations: &[ComplianceViolation]) -> Vec<String> {
        let mut recommendations = Vec::new();

        recommendations.push("Consult with legal counsel in target jurisdictions".to_string());
        recommendations.push("Implement comprehensive KYC/AML procedures".to_string());
        recommendations.push("Screen against OFAC and sanctions lists".to_string());
        recommendations.push("Obtain necessary licenses (money transmitter, securities)".to_string());
        recommendations.push("Implement transaction monitoring and reporting".to_string());
        recommendations.push("Consider geo-blocking prohibited jurisdictions".to_string());

        for violation in violations {
            if matches!(violation.severity, SecuritySeverity::Critical) {
                recommendations.push(format!("URGENT: {}", violation.remediation));
            }
        }

        recommendations
    }

    // Helper methods
    fn has_sanctions_screening(&self) -> bool {
        // Check for external oracle calls for sanctions checking
        // This is simplified - real implementation would check for specific patterns
        false // Most contracts don't have this
    }

    fn interacts_with_tornado_cash(&self) -> bool {
        // Check for Tornado Cash contract addresses in bytecode
        // Tornado Cash addresses: 0x...
        false // Simplified
    }

    fn allows_anonymous_transfers(&self) -> bool {
        // Most contracts allow anonymous transfers by default
        self.bytecode.contains(&0xf1) // Has CALL opcode
    }

    fn has_transaction_limits(&self) -> bool {
        // Check for amount comparisons (LT, GT)
        self.bytecode.windows(2).any(|w| matches!(w[1], 0x10 | 0x11))
    }

    fn has_mixing_pattern(&self) -> bool {
        // Check for mixing patterns (multiple deposits/withdrawals)
        false // Simplified
    }

    fn is_likely_security(&self) -> bool {
        // Howey Test factors:
        // 1. Investment of money
        // 2. Common enterprise
        // 3. Expectation of profits
        // 4. Derived from efforts of others
        
        // Check for profit distribution
        self.has_profit_sharing() && self.has_centralized_management()
    }

    fn has_profit_sharing(&self) -> bool {
        // Look for dividend/yield distribution patterns
        // Multiple CALL operations to distribute funds
        self.bytecode.iter().filter(|&&b| b == 0xf1).count() > 3
    }

    fn has_centralized_management(&self) -> bool {
        // Check for owner/admin patterns
        self.bytecode.windows(2).any(|w| w == &[0x33, 0x14])
    }

    fn stores_personal_data(&self) -> bool {
        // Check for extensive storage operations
        self.bytecode.iter().filter(|&&b| b == 0x55).count() > 5
    }

    fn has_data_deletion(&self) -> bool {
        // Check for delete operations (set to zero pattern)
        self.bytecode.windows(2).any(|w| w == &[0x60, 0x00]) // PUSH 0
    }

    fn facilitates_value_transfer(&self) -> bool {
        // Has external calls with value
        self.bytecode.contains(&0xf1) // CALL
    }

    fn has_licensing_info(&self) -> bool {
        // Check for license storage/verification
        false // Simplified
    }

    pub fn get_high_risk_jurisdictions(&self) -> Vec<String> {
        let report = self.check_compliance();
        report.jurisdiction_risks
            .iter()
            .filter(|(_, &risk)| risk >= 15.0)
            .map(|(jurisdiction, _)| jurisdiction.clone())
            .collect()
    }

    pub fn is_compliant_in(&self, jurisdiction: &str) -> bool {
        let report = self.check_compliance();
        !report.violations.iter().any(|v| v.jurisdiction.contains(&jurisdiction.to_string()))
    }
}
