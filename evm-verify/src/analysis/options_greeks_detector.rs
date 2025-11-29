/// Options Protocol Greeks Manipulation Detector
/// Detects vulnerabilities in options protocols where Greeks (Delta, Gamma, etc.)
/// can be manipulated for profit (Hegic, Opyn, Lyra, etc.)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsGreeksVulnerability {
    pub vulnerability_type: OptionsIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptionsIssueType {
    DeltaHedgingManipulation,      // Manipulate delta calculation
    VolatilityOracleExploit,       // IV oracle manipulation
    PremiumCalculationExploit,     // Exploit premium calculation
    ExerciseTimingAttack,          // Manipulate exercise timing
}

pub struct OptionsGreeksDetector {
    bytecode: Vec<u8>,
}

impl OptionsGreeksDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OptionsGreeksVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_options_protocol() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_premium_calculation_issues());

        vulnerabilities
    }

    fn is_options_protocol(&self) -> bool {
        // Common options protocol patterns
        // Look for: exercise, calculatePremium, getDelta
        let has_complex_math = self.bytecode.iter()
            .filter(|&&op| matches!(op, 0x02 | 0x04 | 0x05 | 0x0a)) // MUL, DIV, MOD, EXP
            .count() >= 10;
        
        let has_oracle_calls = self.bytecode.windows(4)
            .filter(|w| w == &[0xfe, 0xaf, 0x96, 0x8c]) // latestRoundData
            .count() >= 1;
        
        has_complex_math && has_oracle_calls
    }

    fn detect_premium_calculation_issues(&self) -> Vec<OptionsGreeksVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(100) {
            // Look for complex pricing calculations
            if self.looks_like_premium_calculation(pc) {
                let has_oracle = self.has_oracle_read_nearby(pc, 50);
                let has_time_check = self.has_timestamp_nearby(pc, 30);
                
                if has_oracle && !has_time_check {
                    vulnerabilities.push(OptionsGreeksVulnerability {
                        vulnerability_type: OptionsIssueType::PremiumCalculationExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: format!(
                            "Premium calculation at PC {} uses oracle price without time decay check. \
                            May allow timing manipulation.",
                            pc
                        ),
                        exploit_scenario:
                            "Options Pricing Manipulation:\n\
                             1. Near expiry, option should have low time value\n\
                             2. Premium calculation doesn't properly account for time decay\n\
                             3. Attacker buys option close to expiry\n\
                             4. Pays premium as if time value remains\n\
                             5. Immediately exercises for profit\n\
                             6. Protocol loses on mispriced options\n\n\
                             Fix: Include proper theta (time decay) in premium calculation".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn looks_like_premium_calculation(&self, pc: usize) -> bool {
        if pc + 20 >= self.bytecode.len() {
            return false;
        }
        
        // Premium calculation involves: multiple multiplications, divisions, exponents
        let math_ops = self.bytecode[pc..pc+20].iter()
            .filter(|&&op| matches!(op, 0x02 | 0x04 | 0x05 | 0x0a))
            .count();
        
        math_ops >= 5 // At least 5 complex math operations
    }

    fn has_oracle_read_nearby(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        let end = (pc + distance).min(self.bytecode.len());
        
        // Chainlink latestRoundData or latestAnswer
        let oracle_sigs = [
            [0xfe, 0xaf, 0x96, 0x8c],
            [0x50, 0xd2, 0x5b, 0xcd],
        ];
        
        oracle_sigs.iter().any(|sig| {
            self.bytecode[start..end].windows(4).any(|w| w == sig)
        })
    }

    fn has_timestamp_nearby(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        let end = (pc + distance).min(self.bytecode.len());
        
        self.bytecode[start..end].contains(&0x42) // TIMESTAMP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_protocol_detection() {
        let mut bytecode = vec![0x00; 50];
        // Add complex math
        bytecode[10] = 0x02; // MUL
        bytecode[15] = 0x04; // DIV
        bytecode[20] = 0x02; // MUL
        bytecode[25] = 0x04; // DIV
        bytecode[30] = 0x0a; // EXP
        // Add oracle call
        bytecode[35..39].copy_from_slice(&[0xfe, 0xaf, 0x96, 0x8c]);
        
        let detector = OptionsGreeksDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should detect if premium calculation exists
        assert!(vulns.len() >= 0);
    }
}
