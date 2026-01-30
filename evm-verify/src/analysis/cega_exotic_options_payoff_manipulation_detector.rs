// Cega Exotic Options Payoff Manipulation Detector
// Detects vulnerabilities in exotic options structures (barriers, digitals, autocallables)

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CegaExoticOptionsVulnerability {
    pub location: usize,
    pub vulnerability_type: CegaVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CegaVulnerabilityType {
    BarrierManipulation,           // Price pushed through barrier levels
    AutocallTriggerGaming,         // Manipulation of autocall observation dates
    DigitalPayoffRounding,         // Rounding errors in binary payoff calculation
    KnockInKnockOutOrdering,       // KI/KO event ordering exploits
    VolatilitySurfaceManipulation, // IV surface manipulation for pricing
    PayoffCalculationOverflow,     // Arithmetic overflow in complex payoff formulas
    ObservationDateGaming,         // Block timestamp manipulation for observations
}

pub struct CegaExoticOptionsDetector {
    bytecode: Vec<u8>,
}

impl CegaExoticOptionsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CegaExoticOptionsVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect barrier manipulation vulnerabilities
        if let Some(loc) = self.detect_barrier_manipulation() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::BarrierManipulation,
                severity: SecuritySeverity::Critical,
                description: "Barrier level comparison lacks flash loan protection. Attacker can \
                             manipulate underlying price to trigger barrier breach, affecting \
                             knock-in/knock-out options payoff.".to_string(),
                confidence: 0.85,
            });
        }

        // Detect autocall trigger gaming
        if let Some(loc) = self.detect_autocall_gaming() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::AutocallTriggerGaming,
                severity: SecuritySeverity::High,
                description: "Autocall observation lacks TWAP or multi-block averaging. Single \
                             block price check allows MEV to game autocall trigger by temporarily \
                             pushing price above autocall level.".to_string(),
                confidence: 0.80,
            });
        }

        // Detect digital payoff rounding
        if let Some(loc) = self.detect_digital_payoff_rounding() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::DigitalPayoffRounding,
                severity: SecuritySeverity::Medium,
                description: "Binary payoff calculation uses integer division without proper \
                             rounding. Can lead to incorrect payoff amounts near barrier levels.".to_string(),
                confidence: 0.75,
            });
        }

        // Detect knock-in/knock-out ordering issues
        if let Some(loc) = self.detect_knockout_ordering() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::KnockInKnockOutOrdering,
                severity: SecuritySeverity::High,
                description: "KI/KO event checking order is incorrect. If knock-in occurs in same \
                             block as knock-out, the order of checks determines payoff incorrectly.".to_string(),
                confidence: 0.70,
            });
        }

        // Detect volatility surface manipulation
        if let Some(loc) = self.detect_volatility_manipulation() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::VolatilitySurfaceManipulation,
                severity: SecuritySeverity::Critical,
                description: "Option pricing uses spot IV without smile/surface adjustments. \
                             Attacker can manipulate single strike IV to misprice exotic options.".to_string(),
                confidence: 0.82,
            });
        }

        // Detect payoff calculation overflow
        if let Some(loc) = self.detect_payoff_overflow() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::PayoffCalculationOverflow,
                severity: SecuritySeverity::High,
                description: "Complex payoff formula uses unchecked arithmetic. Large price moves \
                             can cause overflow in multi-asset exotic payoff calculation.".to_string(),
                confidence: 0.78,
            });
        }

        // Detect observation date gaming
        if let Some(loc) = self.detect_observation_gaming() {
            vulnerabilities.push(CegaExoticOptionsVulnerability {
                location: loc,
                vulnerability_type: CegaVulnerabilityType::ObservationDateGaming,
                severity: SecuritySeverity::High,
                description: "Observation timestamp uses block.timestamp without bounds. Validators \
                             can manipulate timestamp by ±15s to game barrier observations.".to_string(),
                confidence: 0.73,
            });
        }

        vulnerabilities
    }

    fn detect_barrier_manipulation(&self) -> Option<usize> {
        // Pattern: Price comparison (LT/GT) followed by payoff change without TWAP/protection
        // Looks for: CALL (oracle) → LT/GT (barrier check) → SSTORE (payoff) without averaging
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL/STATICCALL (oracle)
                let mut has_barrier_check = false;
                let mut has_twap = false;
                
                for j in i+1..(i+40).min(self.bytecode.len()) {
                    // Barrier comparison
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_barrier_check = true;
                    }
                    
                    // Check for TWAP (multiple CALLs or averaging)
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                        has_twap = true;
                    }
                    
                    // Payoff update without TWAP
                    if has_barrier_check && !has_twap && self.bytecode[j] == 0x55 {  // SSTORE
                        return Some(i);
                    }
                }
            }
        }
        
        None
    }

    fn detect_autocall_gaming(&self) -> Option<usize> {
        // Pattern: Single block price check for autocall trigger
        // Looks for: TIMESTAMP/NUMBER → CALL (price) → GT (autocall level) → JUMPI (payout)
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 || self.bytecode[i] == 0x43 {  // TIMESTAMP/NUMBER
                let mut has_single_price_check = false;
                let mut price_check_count = 0;
                
                for j in i+1..(i+35).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {  // Price oracle call
                        price_check_count += 1;
                    }
                    
                    // Autocall trigger (price > level)
                    if self.bytecode[j] == 0x11 {  // GT
                        has_single_price_check = true;
                    }
                    
                    // Immediate payout without multi-block check
                    if has_single_price_check && price_check_count == 1 && self.bytecode[j] == 0x57 {  // JUMPI
                        return Some(i);
                    }
                }
            }
        }
        
        None
    }

    fn detect_digital_payoff_rounding(&self) -> Option<usize> {
        // Pattern: Binary payoff calculation using DIV without rounding compensation
        // Looks for: LT/GT (barrier) → JUMPI → MUL → DIV (payoff calc) without ADD (rounding)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {  // LT/GT (barrier check)
                let mut has_multiplication = false;
                let mut has_rounding = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 {  // MUL
                        has_multiplication = true;
                    }
                    
                    // Rounding: ADD before DIV
                    if self.bytecode[j] == 0x01 && has_multiplication {  // ADD
                        has_rounding = true;
                    }
                    
                    // Division without rounding
                    if has_multiplication && !has_rounding && self.bytecode[j] == 0x04 {  // DIV
                        return Some(i);
                    }
                }
            }
        }
        
        None
    }

    fn detect_knockout_ordering(&self) -> Option<usize> {
        // Pattern: Knock-in and knock-out checks in wrong order
        // Looks for: Two barrier checks where KO is checked before KI
        
        let mut first_barrier_loc = None;
        let mut barrier_count = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Barrier check pattern: CALL → LT/GT
            if (self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA) && 
               i + 5 < self.bytecode.len() {
                
                for j in i+1..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        barrier_count += 1;
                        if first_barrier_loc.is_none() {
                            first_barrier_loc = Some(i);
                        }
                        
                        // If we see two barriers close together without proper ordering logic
                        if barrier_count == 2 && !self.has_ordering_logic(first_barrier_loc.unwrap(), i) {
                            return Some(first_barrier_loc.unwrap());
                        }
                        break;
                    }
                }
            }
        }
        
        None
    }

    fn has_ordering_logic(&self, start: usize, end: usize) -> bool {
        // Check if there's AND/OR logic between barriers (proper ordering)
        for i in start..end.min(self.bytecode.len()) {
            if self.bytecode[i] == 0x16 || self.bytecode[i] == 0x17 {  // AND/OR
                return true;
            }
        }
        false
    }

    fn detect_volatility_manipulation(&self) -> Option<usize> {
        // Pattern: IV fetched from single source without smile adjustment
        // Looks for: CALL (IV oracle) → MUL (pricing) without additional CALLs (smile)
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA {  // CALL (IV oracle)
                let mut oracle_call_count = 1;
                let mut has_pricing = false;
                
                for j in i+1..(i+35).min(self.bytecode.len()) {
                    // Count oracle calls (should be multiple for smile)
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                        oracle_call_count += 1;
                    }
                    
                    // Pricing calculation
                    if self.bytecode[j] == 0x02 {  // MUL (pricing)
                        has_pricing = true;
                    }
                    
                    // Single IV source used for pricing
                    if has_pricing && oracle_call_count == 1 && self.bytecode[j] == 0x55 {  // SSTORE
                        return Some(i);
                    }
                }
            }
        }
        
        None
    }

    fn detect_payoff_overflow(&self) -> Option<usize> {
        // Pattern: Multiple multiplications without overflow checks
        // Looks for: MUL → MUL → MUL (complex payoff) without DUP/LT checks
        
        let mut mul_count = 0;
        let mut start_loc = None;
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 {  // MUL
                if start_loc.is_none() {
                    start_loc = Some(i);
                }
                mul_count += 1;
                
                // Check for overflow protection in next few opcodes
                let mut has_overflow_check = false;
                for j in i+1..(i+8).min(self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x80..=0x8F) ||  // DUP
                       matches!(self.bytecode[j], 0x10 | 0x11) {   // LT/GT
                        has_overflow_check = true;
                        break;
                    }
                }
                
                // Multiple MULs without checks
                if mul_count >= 3 && !has_overflow_check {
                    return start_loc;
                }
            } else if !matches!(self.bytecode[i], 0x60..=0x7F) {  // Not PUSH
                // Reset if we hit non-push opcode
                mul_count = 0;
                start_loc = None;
            }
        }
        
        None
    }

    fn detect_observation_gaming(&self) -> Option<usize> {
        // Pattern: TIMESTAMP used for observation without bounds check
        // Looks for: TIMESTAMP → comparison (observation check) without sub/add (bounds)
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_bounds_check = false;
                
                for j in i+1..(i+12).min(self.bytecode.len()) {
                    // Bounds checking: ADD/SUB before comparison
                    if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x03 {  // ADD/SUB
                        has_bounds_check = true;
                    }
                    
                    // Observation check without bounds
                    if !has_bounds_check && (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) {  // LT/GT
                        return Some(i);
                    }
                }
            }
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::CegaExoticOptions,
                severity: v.severity,
                description: format!(
                    "Cega Exotic Options {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_barrier_manipulation_detection() {
        // Bytecode: STATICCALL (oracle) → GT (barrier) → SSTORE (payoff)
        let bytecode = vec![
            0xFA, // STATICCALL (oracle)
            0x60, 0x00, // PUSH1 0
            0x11, // GT (barrier check)
            0x60, 0x01, // PUSH1 1
            0x55, // SSTORE (update payoff)
        ];
        
        let detector = CegaExoticOptionsDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CegaVulnerabilityType::BarrierManipulation)));
    }

    #[test]
    fn test_digital_payoff_rounding() {
        // Bytecode: LT (barrier) → MUL → DIV (no rounding)
        let bytecode = vec![
            0x10, // LT (barrier check)
            0x60, 0x64, // PUSH1 100
            0x02, // MUL
            0x60, 0x0A, // PUSH1 10
            0x04, // DIV (without ADD for rounding)
        ];
        
        let detector = CegaExoticOptionsDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CegaVulnerabilityType::DigitalPayoffRounding)));
    }
}
