// Nonce Reuse Cross Context Detector
// Detects cross-protocol nonce exploitation and replay attacks

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceReuseCrossContextVulnerability {
    pub location: usize,
    pub vulnerability_type: NonceReuseType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NonceReuseType {
    CrossProtocolNonceExploitation,  // Same nonce used across protocols
    CrossChainNonceReuse,            // Nonce reused on different chains
    NonceGapExploitation,            // Exploit gaps in nonce sequence
    NonceOracleManipulation,         // Manipulate external nonce source
    ParallelNonceCollision,          // Collision in parallel execution
    NonceResetVulnerability,         // Nonce counter reset exploit
}

pub struct NonceReuseCrossContextDetector {
    bytecode: Vec<u8>,
}

impl NonceReuseCrossContextDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NonceReuseCrossContextVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_cross_protocol_nonce_exploitation() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::CrossProtocolNonceExploitation,
                severity: "Critical".to_string(),
                description: "Nonce not protocol-specific. Same nonce can be used across different \
                             protocols enabling cross-protocol replay attacks.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_cross_chain_nonce_reuse() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::CrossChainNonceReuse,
                severity: "Critical".to_string(),
                description: "Nonce not chain-specific. Transaction replay possible across different \
                             chains (mainnet, testnets, L2s) with same signature.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_nonce_gap_exploitation() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::NonceGapExploitation,
                severity: "High".to_string(),
                description: "Nonce sequence gaps not prevented. Skipped nonces can be exploited \
                             later for out-of-order transaction execution.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_nonce_oracle_manipulation() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::NonceOracleManipulation,
                severity: "High".to_string(),
                description: "External nonce source manipulable. Attacker can control nonce values \
                             through oracle manipulation enabling replay attacks.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_parallel_nonce_collision() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::ParallelNonceCollision,
                severity: "High".to_string(),
                description: "Parallel transaction execution allows nonce collision. Race conditions \
                             in nonce generation enable duplicate nonce usage.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_nonce_reset_vulnerability() {
            vulnerabilities.push(NonceReuseCrossContextVulnerability {
                location: loc,
                vulnerability_type: NonceReuseType::NonceResetVulnerability,
                severity: "Critical".to_string(),
                description: "Nonce counter resettable by authorized party. Reset enables reuse of \
                             old nonces for replay attacks on historical transactions.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_cross_protocol_nonce_exploitation(&self) -> Option<usize> {
        // Pattern: Nonce check without protocol identifier
        // SLOAD nonce without including protocol context
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (nonce)
                let mut is_nonce_check = false;
                let mut includes_protocol_context = false;
                
                // Check if nonce verification
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 || self.bytecode[j] == 0x10 {  // EQ/LT (nonce check)
                        is_nonce_check = true;
                    }
                }
                
                // Check for protocol context (hash with protocol identifier)
                for j in (i.saturating_sub(20))..i {
                    // Protocol ID should be hashed with address
                    if self.bytecode[j] == 0x20 {  // SHA3 (hash key with protocol)
                        includes_protocol_context = true;
                    }
                }
                
                if is_nonce_check && !includes_protocol_context {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cross_chain_nonce_reuse(&self) -> Option<usize> {
        // Pattern: Signature verification without chain ID
        // ECRECOVER without CHAINID in signed message
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut has_chain_id = false;
                
                // Check for CHAINID in message hash
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x46 {  // CHAINID opcode
                        has_chain_id = true;
                    }
                    
                    // Alternative: hardcoded chain ID constant
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH (chain ID)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x20 {  // SHA3 (hash with chain ID)
                                has_chain_id = true;
                            }
                        }
                    }
                }
                
                if !has_chain_id {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_nonce_gap_exploitation(&self) -> Option<usize> {
        // Pattern: Nonce increment without gap check
        // Allows skipping nonces creating exploitable gaps
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update nonce)
                let mut is_nonce_update = false;
                let mut enforces_sequential = false;
                
                // Check if nonce update (increment)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increment)
                        is_nonce_update = true;
                    }
                }
                
                // Check for sequential enforcement (new = old + 1)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (old nonce)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD 1
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x14 {  // EQ (exactly old + 1)
                                        enforces_sequential = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_nonce_update && !enforces_sequential {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_nonce_oracle_manipulation(&self) -> Option<usize> {
        // Pattern: Nonce from external source without validation
        // STATICCALL result used as nonce without verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (external nonce)
                let mut used_as_nonce = false;
                let mut has_validation = false;
                
                // Check if result used as nonce
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (nonce check)
                        used_as_nonce = true;
                    }
                }
                
                // Check for validation (monotonic increase, bounds)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 {  // LT (compare with previous)
                        has_validation = true;
                    }
                }
                
                if used_as_nonce && !has_validation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_parallel_nonce_collision(&self) -> Option<usize> {
        // Pattern: Nonce generation without atomic increment
        // Race condition in nonce allocation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (read nonce)
                let mut has_increment = false;
                let mut has_lock = false;
                
                // Check for increment after read
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 {  // ADD
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE (update)
                                has_increment = true;
                            }
                        }
                    }
                }
                
                // Check for lock/mutex (reentrancy guard)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (lock flag)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check unlocked)
                                has_lock = true;
                            }
                        }
                    }
                }
                
                if has_increment && !has_lock {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_nonce_reset_vulnerability(&self) -> Option<usize> {
        // Pattern: Nonce counter reset function
        // SSTORE that sets nonce to zero or lower value
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set nonce)
                let mut is_nonce_storage = false;
                let mut sets_lower_value = false;
                
                // Check if nonce storage slot
                for j in (i.saturating_sub(15))..i {
                    // Nonce typically at specific slot
                    if self.bytecode[j] == 0x54 {  // SLOAD (current nonce)
                        is_nonce_storage = true;
                    }
                }
                
                // Check if setting to zero or lower
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() {
                        if self.bytecode[j+1] == 0x00 {  // PUSH1 0 (reset)
                            sets_lower_value = true;
                        }
                    }
                    if self.bytecode[j] == 0x03 {  // SUB (decrease)
                        sets_lower_value = true;
                    }
                }
                
                if is_nonce_storage && sets_lower_value {
                    return Some(i);
                }
            }
        }
        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_protocol_nonce_exploitation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (nonce without protocol context)
            0x60, 0x01, // PUSH1 1
            0x14, // EQ (check nonce)
        ];
        
        let detector = NonceReuseCrossContextDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, NonceReuseType::CrossProtocolNonceExploitation)));
    }

    #[test]
    fn test_cross_chain_nonce_reuse() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x01, // ECRECOVER (without CHAINID)
        ];
        
        let detector = NonceReuseCrossContextDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, NonceReuseType::CrossChainNonceReuse)));
    }
}
