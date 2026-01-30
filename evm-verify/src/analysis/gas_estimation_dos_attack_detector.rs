use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimationDosVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Gas Estimation DoS Attack Detector
///
/// Detects vulnerabilities where gas estimation can fail or return incorrect values,
/// enabling denial of service attacks or causing legitimate transactions to fail.
///
/// Attack Vectors:
/// - Unbounded loops that break gas estimation
/// - Variable gas consumption based on state
/// - Fallback functions with unpredictable gas usage
/// - External calls with unknown gas requirements
/// - Gas estimation griefing in batch operations
///
/// Real-World Cases:
/// - GovernorBravo: gas estimation failures blocked voting
/// - Multiple DeFi protocols: batch operations DoS
/// - NFT mints: gas estimation manipulation
/// - DEX aggregators: routing failures due to gas estimation
///
/// Detection Strategy:
/// - Identifies unbounded loops in user-facing functions
/// - Detects state-dependent gas consumption patterns
/// - Looks for external calls without gas limits
/// - Checks for fallback/receive with complex logic
/// - Identifies gas-griefing attack vectors
pub struct GasEstimationDosAttackDetector;

impl GasEstimationDosAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Unbounded loop (gas estimation fails)
            if bytecode[i] == 0x57 {
                if self.has_unbounded_loop(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unbounded loop detected: Gas estimation cannot determine upper bound, enabling DoS attacks".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: State-dependent gas consumption
            if bytecode[i] == 0x54 {
                if self.has_state_dependent_gas_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "State-dependent gas: Gas consumption varies with state, causing estimation failures and DoS".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: External call in loop (gas estimation griefing)
            if bytecode[i] == 0xf1 || bytecode[i] == 0xfa {
                if self.has_external_call_in_loop(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "External call in loop: Gas estimation vulnerable to griefing, single malicious contract can DoS entire batch".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 4: Complex fallback/receive (estimation failure)
            if bytecode[i] == 0x36 {
                if self.has_complex_fallback_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Complex fallback function: Unpredictable gas usage breaks estimation for contracts sending ETH".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Array iteration without bounds check
            if bytecode[i] == 0x02 {
                if self.has_unbounded_array_iteration(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unbounded array iteration: Gas estimation fails on large arrays, enabling DoS via array growth".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<GasEstimationDosVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| GasEstimationDosVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_unbounded_loop(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_loop_counter = false;
        let mut has_bound_check = false;
        let mut has_storage_read = false;
        let mut counter_operations = 0;

        // Check for loop structure
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x01 | 0x03 => counter_operations += 1, // ADD, SUB (counter update)
                    0x10 | 0x11 => has_bound_check = true, // LT, GT (bound check)
                    0x54 => has_storage_read = true, // SLOAD (array length or bound)
                    0x80..=0x8f => has_loop_counter = true, // DUP (counter manipulation)
                    _ => {}
                }
            }
        }

        // Unbounded loop: has counter but no clear upper bound
        counter_operations >= 2 && has_loop_counter && !has_bound_check && has_storage_read
    }

    fn has_state_dependent_gas_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut conditional_on_storage = false;
        let mut has_jumpi = false;
        let mut has_loop = false;
        let mut sload_count = 1; // Current SLOAD

        // Check if storage value controls execution
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x57 => {
                        has_jumpi = true;
                        conditional_on_storage = true;
                    }
                    0x54 => sload_count += 1, // Multiple storage reads
                    0x14 | 0x10 | 0x11 => {
                        // Comparison with storage value
                        if !has_jumpi {
                            conditional_on_storage = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for loop after conditional
        if has_jumpi && pos + 15 < bytecode.len() {
            for offset in 1..15 {
                if pos + offset < bytecode.len() && bytecode[pos + offset] == 0x57 {
                    has_loop = true;
                    break;
                }
            }
        }

        // State-dependent branching or looping
        conditional_on_storage && (has_jumpi || has_loop) && sload_count >= 2
    }

    fn has_external_call_in_loop(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut in_loop = false;
        let mut has_iteration = false;
        let mut has_array_access = false;

        // Check for loop context
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => in_loop = true, // JUMPI
                    0x01 | 0x03 => has_iteration = true, // ADD, SUB (iterator)
                    0x02 => has_array_access = true, // MUL (array indexing)
                    _ => {}
                }
            }
        }

        // External call in loop with array access
        in_loop && has_iteration && has_array_access
    }

    fn has_complex_fallback_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let mut is_fallback = false;
        let mut has_complex_logic = false;
        let mut operation_count = 0;
        let mut has_external_call = false;

        // CALLDATASIZE at function start suggests fallback check
        is_fallback = bytecode[pos] == 0x36;

        // Check complexity after CALLDATASIZE
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x54 | 0x55 => operation_count += 3, // Storage operations (expensive)
                    0xf1 | 0xfa | 0xf4 => {
                        has_external_call = true;
                        operation_count += 5;
                    }
                    0x57 => operation_count += 1, // JUMPI (branching)
                    0x20 => operation_count += 2, // KECCAK256 (expensive)
                    _ => {}
                }
            }
        }

        // Complex fallback: many operations or external calls
        is_fallback && (operation_count >= 10 || has_external_call)
    }

    fn has_unbounded_array_iteration(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let window = 35.min(bytecode.len().saturating_sub(pos));
        
        let mut has_array_length = false;
        let mut has_loop = false;
        let mut has_iteration = false;
        let mut mul_for_indexing = bytecode[pos] == 0x02;

        // Check for array length load
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => has_array_length = true, // SLOAD (array length)
                    0x01 | 0x03 => has_iteration = true, // ADD, SUB (iterator)
                    _ => {}
                }
            }
        }

        // Check for loop after MUL
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x57 {
                    has_loop = true;
                    break;
                }
            }
        }

        // Array iteration with MUL for indexing and loop
        mul_for_indexing && has_array_length && has_loop && has_iteration
    }
}
