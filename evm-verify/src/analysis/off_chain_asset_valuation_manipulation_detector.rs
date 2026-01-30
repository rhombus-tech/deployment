// Off-Chain Asset Valuation Manipulation Detector
// Detects NAV oracle attacks and asset pricing manipulation for RWAs

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffChainAssetValuationVulnerability {
    pub location: usize,
    pub vulnerability_type: OffChainValuationType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OffChainValuationType {
    NAVOracleManipulation,           // Net Asset Value oracle compromised
    AppraisalDataFalsification,      // Fake or manipulated appraisal data
    AssetPriceDiscrepancy,           // On-chain vs off-chain price mismatch
    ValuationTimingExploit,          // Exploit stale valuations
    ThirdPartyDataCorruption,        // Corrupted third-party pricing feeds
    RedemptionValueMismatch,         // Redemption price differs from NAV
}

pub struct OffChainAssetValuationDetector {
    bytecode: Vec<u8>,
}

impl OffChainAssetValuationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OffChainAssetValuationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_nav_oracle_manipulation() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::NAVOracleManipulation,
                severity: SecuritySeverity::Critical,
                description: "NAV oracle uses single source without validation. Off-chain asset \
                             valuation can be manipulated through compromised oracle.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_appraisal_data_falsification() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::AppraisalDataFalsification,
                severity: SecuritySeverity::Critical,
                description: "Appraisal data accepted without cryptographic verification. Falsified \
                             valuations can inflate or deflate asset prices maliciously.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_asset_price_discrepancy() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::AssetPriceDiscrepancy,
                severity: SecuritySeverity::High,
                description: "No reconciliation between on-chain token price and off-chain asset \
                             value. Arbitrage exploits possible through price divergence.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_valuation_timing_exploit() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::ValuationTimingExploit,
                severity: SecuritySeverity::High,
                description: "Valuation staleness not checked. Outdated asset values used for \
                             critical operations enabling arbitrage or manipulation.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_third_party_data_corruption() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::ThirdPartyDataCorruption,
                severity: SecuritySeverity::High,
                description: "Third-party data feeds lack integrity verification. Corrupted or \
                             malicious data can affect asset valuations.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_redemption_value_mismatch() {
            vulnerabilities.push(OffChainAssetValuationVulnerability {
                location: loc,
                vulnerability_type: OffChainValuationType::RedemptionValueMismatch,
                severity: SecuritySeverity::Critical,
                description: "Redemption value calculation differs from NAV. Users receive incorrect \
                             amounts during redemption enabling value extraction.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_nav_oracle_manipulation(&self) -> Option<usize> {
        // Pattern: Single oracle call for NAV without validation
        // STATICCALL to oracle without multi-source verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (oracle query)
                let mut is_nav_query = false;
                let mut has_multi_source = false;
                
                // Check if NAV/price query (result used in calculations)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV (price calc)
                        is_nav_query = true;
                    }
                }
                
                // Check for multiple oracle sources (additional STATICCALLs)
                let mut oracle_count = 1;
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // Another STATICCALL
                        oracle_count += 1;
                    }
                }
                
                has_multi_source = oracle_count >= 2;
                
                if is_nav_query && !has_multi_source {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_appraisal_data_falsification(&self) -> Option<usize> {
        // Pattern: Appraisal data used without signature verification
        // CALLDATALOAD for appraisal without ECRECOVER
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (appraisal data)
                let mut used_for_valuation = false;
                let mut has_signature_check = false;
                
                // Check if used in valuation (stored or used in calculations)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 || self.bytecode[j] == 0x02 {  // SSTORE or MUL
                        used_for_valuation = true;
                    }
                }
                
                // Check for signature verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 {  // ECRECOVER
                        has_signature_check = true;
                    }
                }
                
                if used_for_valuation && !has_signature_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_asset_price_discrepancy(&self) -> Option<usize> {
        // Pattern: Token price and NAV used without reconciliation
        // Two separate price values without comparison
        
        let mut price_loads = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (price)
                price_loads.push(i);
            }
        }
        
        // Multiple price values without comparison
        if price_loads.len() >= 2 {
            let mut has_comparison = false;
            
            for window in price_loads.windows(2) {
                let start = window[0];
                let end = window[1];
                
                // Check for comparison between the two prices
                for i in start..end.min(start + 30) {
                    if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {  // LT/GT
                        has_comparison = true;
                    }
                }
            }
            
            if !has_comparison {
                return Some(price_loads[0]);
            }
        }
        
        None
    }

    fn detect_valuation_timing_exploit(&self) -> Option<usize> {
        // Pattern: Valuation used without staleness check
        // Price/NAV loaded without timestamp validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (valuation)
                let mut used_in_operation = false;
                let mut checks_timestamp = false;
                
                // Check if used in critical operation
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0xF1 {  // MUL or CALL
                        used_in_operation = true;
                    }
                }
                
                // Check for timestamp staleness verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (age calculation)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (not too old)
                                        checks_timestamp = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if used_in_operation && !checks_timestamp {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_third_party_data_corruption(&self) -> Option<usize> {
        // Pattern: External data used without integrity check
        // STATICCALL result used without validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (external data)
                let mut data_used = false;
                let mut has_integrity_check = false;
                
                // Check if result used
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (store result)
                        data_used = true;
                    }
                }
                
                // Check for integrity verification (hash check or multi-source)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // SHA3 (hash verification)
                        has_integrity_check = true;
                    }
                    if self.bytecode[j] == 0xFA {  // Another source
                        has_integrity_check = true;
                    }
                }
                
                if data_used && !has_integrity_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_redemption_value_mismatch(&self) -> Option<usize> {
        // Pattern: Redemption calculation differs from NAV
        // Two different price calculations without consistency check
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x02 {  // MUL (redemption value calc)
                let mut is_redemption = false;
                let mut uses_same_nav = false;
                
                // Check if redemption calculation (followed by transfer)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 {  // CALL (transfer)
                        is_redemption = true;
                    }
                }
                
                // Check if same NAV value used (SLOAD from same slot)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (NAV)
                        // Check if this same slot loaded elsewhere for consistency
                        for k in i+1..(i+30).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // Same SLOAD
                                uses_same_nav = true;
                            }
                        }
                    }
                }
                
                if is_redemption && !uses_same_nav {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("OffChainAssetValuation{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Off-Chain Asset Valuation {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement multi-source oracle validation, cryptographic signatures for \
                             appraisals, staleness checks, integrity verification for external data, \
                             and consistent pricing across redemption and valuation".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nav_oracle_manipulation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0xFA, // STATICCALL (single oracle - no validation)
            0x60, 0x64, // PUSH1 100
            0x02, // MUL (use in calculation)
        ];
        
        let detector = OffChainAssetValuationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, OffChainValuationType::NAVOracleManipulation)));
    }

    #[test]
    fn test_valuation_timing_exploit() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (valuation without staleness check)
            0x60, 0x0A, // PUSH1 10
            0x02, // MUL (use stale value)
        ];
        
        let detector = OffChainAssetValuationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, OffChainValuationType::ValuationTimingExploit)));
    }
}
