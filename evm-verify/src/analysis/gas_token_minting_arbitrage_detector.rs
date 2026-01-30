use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasTokenArbitrageVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Gas Token Minting Arbitrage Detector
///
/// Detects patterns related to gas token minting/burning for arbitrage, which can be
/// exploited for DoS attacks, economic manipulation, or to game gas refund mechanisms.
///
/// Gas Token Mechanisms:
/// - CHI/GST2 tokens mint during low gas prices, burn for refunds during high prices
/// - SSTORE from non-zero to zero gives gas refund (pre-London)
/// - SELFDESTRUCT gives gas refund (pre-London)
/// - Storage slot clearing for refunds can be abused
///
/// Attack Vectors:
/// - Mass minting to bloat state, then burning for refunds
/// - DoS via storage manipulation and refund gaming
/// - Transaction ordering manipulation via gas refunds
/// - Economic attacks exploiting refund asymmetries
///
/// Real-World Cases:
/// - GasToken attacks causing state bloat on Ethereum
/// - Refund gaming in DeFi protocols
/// - Transaction reordering exploits via gas manipulation
/// - EIP-3529 (London) disabled many refund mechanisms
///
/// Detection Strategy:
/// - Identifies repeated SSTORE patterns (minting/burning)
/// - Detects SELFDESTRUCT in loops or arrays
/// - Looks for storage clearing patterns
/// - Checks for gas refund exploitation
/// - Identifies gas-dependent arbitrage logic
pub struct GasTokenMintingArbitrageDetector;

impl GasTokenMintingArbitrageDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Mass storage clearing (gas refund exploitation)
            if bytecode[i] == 0x55 {
                if self.has_mass_storage_clearing(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Gas token pattern: Mass storage clearing for gas refunds, can be exploited for DoS or economic attacks".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: Loop-based SELFDESTRUCT (GST2-style gas token)
            if bytecode[i] == 0xff {
                if self.has_loop_selfdestruct_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Gas token SELFDESTRUCT: Loop-based self-destruct pattern typical of GST2 gas tokens, high DoS risk".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 3: Storage slot cycling (CHI-style gas token)
            if bytecode[i] == 0x55 {
                if self.has_storage_slot_cycling(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Storage slot cycling: CHI-style gas token pattern, exploits SSTORE refunds for arbitrage".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 4: Gas price dependent minting/burning
            if bytecode[i] == 0x3a {
                if self.has_gas_price_dependent_logic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Gas price arbitrage: Logic depends on gas price for minting/burning decisions, typical gas token behavior".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Batch storage operations (state bloat risk)
            if bytecode[i] == 0x55 {
                if self.has_batch_storage_operations(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Batch storage operations: Large-scale storage writes can bloat state or exploit refund mechanics".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<GasTokenArbitrageVulnerability> {
        self.detect(bytecode)
            .into_iter()
            .map(|finding| GasTokenArbitrageVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_mass_storage_clearing(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let window = 40.min(bytecode.len().saturating_sub(pos));
        
        let mut sstore_count = 1; // Current SSTORE
        let mut has_loop = false;
        let mut has_zero_value = false;
        let mut has_counter = false;

        // Check for zero value (clearing)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x60 if pos >= offset + 1 => {
                        // PUSH1 0
                        if bytecode.get(pos - offset + 1) == Some(&0x00) {
                            has_zero_value = true;
                        }
                    }
                    0x57 => has_loop = true, // JUMPI (loop)
                    0x01 => has_counter = true, // ADD (counter increment)
                    _ => {}
                }
            }
        }

        // Count additional SSTOREs in loop
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x55 {
                    sstore_count += 1;
                }
            }
        }

        // Mass clearing: loop with zero SSTOREs
        has_zero_value && has_loop && sstore_count >= 2 && has_counter
    }

    fn has_loop_selfdestruct_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut has_loop = false;
        let mut has_counter = false;
        let mut has_array_access = false;

        // Check for loop structure
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => has_loop = true, // JUMPI
                    0x01 => has_counter = true, // ADD (counter)
                    0x02 => has_array_access = true, // MUL (array indexing)
                    0xf0 | 0xf5 => has_array_access = true, // CREATE, CREATE2 (contract array)
                    _ => {}
                }
            }
        }

        // SELFDESTRUCT in loop with array access (GST2 pattern)
        has_loop && has_counter && has_array_access
    }

    fn has_storage_slot_cycling(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let window = 40.min(bytecode.len().saturating_sub(pos));
        
        let mut sload_before = false;
        let mut sstore_count = 1; // Current SSTORE
        let mut has_slot_increment = false;
        let mut has_conditional = false;

        // Check for SLOAD before SSTORE (read-modify-write)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => sload_before = true, // SLOAD
                    0x01 => has_slot_increment = true, // ADD (slot increment)
                    0x57 => has_conditional = true, // JUMPI
                    _ => {}
                }
            }
        }

        // Count nearby SSTOREs
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x55 {
                    sstore_count += 1;
                }
            }
        }

        // Slot cycling: SLOAD, modify, SSTORE with slot incrementing
        sload_before && sstore_count >= 2 && has_slot_increment && has_conditional
    }

    fn has_gas_price_dependent_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_threshold = false;
        let mut has_mint_burn = false;

        // Check for gas price comparison and actions
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x11 => has_comparison = true, // LT, GT (threshold comparison)
                    0x60..=0x7f => has_threshold = true, // PUSH (threshold value)
                    0x55 | 0xff => has_mint_burn = true, // SSTORE or SELFDESTRUCT
                    _ => {}
                }
            }
        }

        // GASPRICE comparison leading to mint/burn operations
        has_comparison && has_threshold && has_mint_burn
    }

    fn has_batch_storage_operations(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let window = 60.min(bytecode.len().saturating_sub(pos));
        
        let mut sstore_count = 1; // Current SSTORE
        let mut has_loop = false;
        let mut has_array_iteration = false;
        let mut iteration_operations = 0;

        // Check for loop/array iteration
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => has_loop = true, // JUMPI
                    0x02 => has_array_iteration = true, // MUL (array indexing)
                    0x01 | 0x03 => iteration_operations += 1, // ADD, SUB
                    _ => {}
                }
            }
        }

        // Count SSTOREs in batch
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x55 {
                    sstore_count += 1;
                }
            }
        }

        // Batch operations: loop with many SSTOREs
        has_loop && sstore_count >= 5 && (has_array_iteration || iteration_operations >= 2)
    }
}
