use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseFeeOpcodeVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// BASEFEE Opcode London Upgrade Detector
///
/// Detects vulnerabilities related to the BASEFEE opcode (0x48) introduced in the London
/// hard fork (EIP-1559). Pre-London chains don't support this opcode, causing failures.
///
/// Vulnerability Scenarios:
/// - Contracts using BASEFEE fail on pre-London chains
/// - Gas price calculations break when BASEFEE is unavailable
/// - Priority fee logic depends on BASEFEE availability
/// - Cross-chain contracts with inconsistent BASEFEE support
/// - Relayers and transaction builders assuming BASEFEE exists
///
/// Real-World Impact:
/// - Transaction relayers breaking on non-EIP-1559 chains
/// - DeFi protocols with gas-dependent logic failing
/// - Cross-chain bridges with incompatible fee calculations
/// - MEV bots unable to operate on certain chains
///
/// Detection Strategy:
/// - Identifies BASEFEE usage without fallback logic
/// - Detects gas calculations depending solely on BASEFEE
/// - Looks for EIP-1559 assumptions in fee logic
/// - Checks for BASEFEE in critical paths without version detection
/// - Identifies missing London hard fork compatibility checks
pub struct BasefeeOpcodeLondonUpgradeDetector {
    bytecode: Vec<u8>,
}

impl BasefeeOpcodeLondonUpgradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<BaseFeeOpcodeVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| BaseFeeOpcodeVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: BASEFEE without fallback (London incompatibility)
            if bytecode[i] == 0x48 {
                if self.has_basefee_without_fallback(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "BASEFEE London upgrade risk: Using BASEFEE without fallback breaks on pre-London chains".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: BASEFEE in gas price calculations
            if bytecode[i] == 0x48 {
                if self.has_basefee_in_gas_calculation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "BASEFEE gas calculation: Gas price logic depends on BASEFEE, incompatible with pre-EIP-1559 chains".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: BASEFEE with GASPRICE (EIP-1559 fee separation)
            if bytecode[i] == 0x48 {
                if self.has_basefee_with_gasprice_confusion(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "BASEFEE/GASPRICE confusion: Mixing BASEFEE and GASPRICE may cause incorrect fee calculations across chains".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: BASEFEE in transaction validation
            if bytecode[i] == 0x48 {
                if self.has_basefee_in_validation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "BASEFEE validation: Transaction validation logic uses BASEFEE, may reject valid txs on non-London chains".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: Multiple BASEFEE operations (complex EIP-1559 logic)
            if bytecode[i] == 0x48 {
                if self.has_complex_basefee_logic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Complex BASEFEE logic: Multiple BASEFEE operations increase London hard fork compatibility risks".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_basefee_without_fallback(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        let lookback = 15.min(pos);
        
        let mut has_existence_check = false;
        let mut has_alternative = false;

        // Check for BASEFEE existence validation
        for offset in 1..=lookback {
            if pos >= offset {
                // Check for try/catch pattern or version check
                if bytecode[pos - offset] == 0x57 { // JUMPI (could be version check)
                    has_existence_check = true;
                }
            }
        }

        // Check for GASPRICE fallback
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x3a { // GASPRICE (fallback)
                    has_alternative = true;
                    break;
                }
            }
        }

        // BASEFEE without proper fallback
        !has_existence_check || !has_alternative
    }

    fn has_basefee_in_gas_calculation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_arithmetic = false;
        let mut has_gas_related = false;
        let mut has_comparison = false;

        // Check for gas-related calculations with BASEFEE
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x01 | 0x02 | 0x03 => has_arithmetic = true, // ADD, MUL, SUB
                    0x5a => has_gas_related = true, // GAS
                    0x3a => has_gas_related = true, // GASPRICE
                    0x10 | 0x11 => has_comparison = true, // LT, GT (fee comparison)
                    _ => {}
                }
            }
        }

        // BASEFEE used in gas calculations
        has_arithmetic && (has_gas_related || has_comparison)
    }

    fn has_basefee_with_gasprice_confusion(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let lookback = 40.min(pos);
        
        let mut has_gasprice_before = false;
        let mut has_gasprice_after = false;
        let mut has_arithmetic = false;

        // Check for GASPRICE usage near BASEFEE
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x3a => has_gasprice_before = true, // GASPRICE
                    0x01 | 0x03 => has_arithmetic = true, // ADD, SUB
                    _ => {}
                }
            }
        }

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x3a => has_gasprice_after = true, // GASPRICE
                    0x01 | 0x03 => has_arithmetic = true, // ADD, SUB
                    _ => {}
                }
            }
        }

        // Mixing BASEFEE and GASPRICE in calculations
        (has_gasprice_before || has_gasprice_after) && has_arithmetic
    }

    fn has_basefee_in_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_revert = false;
        let mut has_jumpi = false;

        // Check for validation pattern after BASEFEE
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x11 | 0x14 => has_comparison = true, // LT, GT, EQ
                    0xfd => has_revert = true, // REVERT
                    0x57 => has_jumpi = true, // JUMPI (conditional)
                    _ => {}
                }
            }
        }

        // BASEFEE in validation logic
        has_comparison && (has_revert || has_jumpi)
    }

    fn has_complex_basefee_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 80.min(bytecode.len().saturating_sub(pos));
        let mut basefee_count = 1; // Current BASEFEE
        let mut arithmetic_ops = 0;

        // Count additional BASEFEE and operations
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x48 => basefee_count += 1, // Additional BASEFEE
                    0x01..=0x05 => arithmetic_ops += 1, // Arithmetic operations
                    _ => {}
                }
            }
        }

        // Multiple BASEFEE with complex calculations
        basefee_count >= 2 || (basefee_count >= 1 && arithmetic_ops >= 5)
    }
}
