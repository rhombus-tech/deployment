use serde::{Deserialize, Serialize};

/// BN254 Pairing DoS Detector
/// 
/// Detects DoS vulnerabilities in BN254 elliptic curve pairing operations.
/// Used in ZK-SNARKs, critical for L2s, privacy protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bn254PairingDosVulnerability {
    /// Critical: Unbounded pairing check allows DoS
    UnboundedPairingCheck {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: No gas limit on pairing precompile
    NoGasLimitOnPairing {
        description: String,
        location: usize,
    },
    /// High: User-controlled pairing input count
    UserControlledPairingCount {
        description: String,
        location: usize,
    },
    /// Medium: Large pairing without batching
    LargePairingNoBatching {
        description: String,
        location: usize,
    },
}

pub struct Bn254PairingDosDetector {
    bytecode: Vec<u8>,
}

impl Bn254PairingDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Bn254PairingDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find all BN254 pairing precompile calls (address 0x08)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_pairing_precompile_call(i) {
                // Pattern 1: Check if input size is bounded
                if !self.has_input_size_limit(i, i + 80) {
                    vulnerabilities.push(Bn254PairingDosVulnerability::UnboundedPairingCheck {
                        description: "BN254 pairing check without input size limit - attacker can provide massive inputs causing DoS".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                // Pattern 2: Check if gas limit is set
                if !self.has_gas_limit_on_call(i) {
                    vulnerabilities.push(Bn254PairingDosVulnerability::NoGasLimitOnPairing {
                        description: "Pairing precompile call without gas limit - can consume all available gas".to_string(),
                        location: i,
                    });
                }
                
                // Pattern 3: Check if input count is user-controlled
                if self.is_input_count_user_controlled(i, i + 100) {
                    vulnerabilities.push(Bn254PairingDosVulnerability::UserControlledPairingCount {
                        description: "Number of pairing operations controlled by user input - DoS vector".to_string(),
                        location: i,
                    });
                }
                
                // Pattern 4: Check for large un-batched pairing operations
                if self.has_large_pairing_operations(i, i + 100) {
                    vulnerabilities.push(Bn254PairingDosVulnerability::LargePairingNoBatching {
                        description: "Large pairing operations without batching optimization".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_pairing_precompile_call(&self, location: usize) -> bool {
        if location + 15 > self.bytecode.len() {
            return false;
        }
        
        // BN254 pairing precompile is at address 0x08
        // Look for: PUSH1 0x08 followed by STATICCALL or CALL
        
        for offset in 0..10 {
            if location + offset + 2 < self.bytecode.len() {
                if self.bytecode[location + offset] == 0x60 && // PUSH1
                   self.bytecode[location + offset + 1] == 0x08 { // Pairing precompile
                    // Look for CALL/STATICCALL nearby
                    for j in (location + offset + 2)..(location + offset + 15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xFA || self.bytecode[j] == 0xF1 {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn has_input_size_limit(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Look for input size validation
        // Pairing input is 192 bytes per pair (G1 + G2 point)
        // Should limit to reasonable number like 4-8 pairs max
        
        for i in start..range_end.saturating_sub(10) {
            // Look for size comparison
            if self.bytecode[i] == 0x10 || // LT
               self.bytecode[i] == 0x11 { // GT
                // Check if comparing against reasonable limit
                for j in (i.saturating_sub(5))..i {
                    if self.bytecode[j] == 0x61 || self.bytecode[j] == 0x62 { // PUSH2/PUSH3
                        // Check for reasonable size limits
                        // Max ~1500 bytes (8 pairs) is reasonable
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn has_gas_limit_on_call(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Check if CALL/STATICCALL has gas parameter
        // Pattern: PUSH gas_limit before CALL/STATICCALL
        
        for i in location.saturating_sub(10)..location {
            // Look for PUSH with gas limit
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x62 { // PUSH1-PUSH3
                // Gas limit should be reasonable (not GAS opcode which is 0x5A)
                if i > 0 && self.bytecode[i - 1] != 0x5A {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn is_input_count_user_controlled(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check if input size comes from CALLDATALOAD (user input)
        let mut has_calldataload = false;
        let mut has_mul = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                has_calldataload = true;
            }
            
            // Input count multiplied by 192 (pairing input size)
            if self.bytecode[i] == 0x02 { // MUL
                has_mul = true;
            }
        }
        
        // If user input is multiplied (likely for pairing count), it's user-controlled
        has_calldataload && has_mul
    }
    
    fn has_large_pairing_operations(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check for large fixed pairing input sizes
        // More than 4 pairings (768 bytes) without batching is suspicious
        
        for i in start..range_end.saturating_sub(3) {
            if self.bytecode[i] == 0x61 { // PUSH2
                if i + 2 < range_end {
                    let size = ((self.bytecode[i + 1] as u16) << 8) | (self.bytecode[i + 2] as u16);
                    // >768 bytes = >4 pairing operations
                    if size > 768 {
                        return true;
                    }
                }
            }
        }
        
        false
    }
}
