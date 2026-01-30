use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MultisigSignerCoordinationFailureDetector {
    bytecode: Vec<u8>,
}

impl MultisigSignerCoordinationFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MultisigVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect threshold comparison without timeout checking
        vulnerabilities.extend(self.detect_threshold_without_timeout());
        
        // Detect signature storage without removal mechanism
        vulnerabilities.extend(self.detect_permanent_signature_storage());
        
        // Detect execution without cancellation path
        vulnerabilities.extend(self.detect_no_cancellation());

        vulnerabilities
    }

    fn detect_threshold_without_timeout(&self) -> Vec<MultisigVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for LT/GT (threshold comparison)
            if opcode == 0x10 || opcode == 0x11 { // LT or GT
                let window_start = if pc > 50 { pc - 50 } else { 0 };
                let window_end = (pc + 50).min(self.bytecode.len());
                
                // Check if SLOAD nearby (loading signature count)
                let has_sload = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x54);
                
                // Check if TIMESTAMP check exists (timeout mechanism)
                let has_timestamp = self.bytecode[window_start..window_end].iter().any(|&b| b == 0x42);
                
                if has_sload && !has_timestamp {
                    vulns.push(MultisigVulnerability {
                        pc,
                        vulnerability_type: "ThresholdWithoutTimeout".to_string(),
                        description: format!(
                            "Threshold comparison at PC {} without timeout check. Multisig can become stuck if: \
                            (1) Required signers become unavailable, (2) Keys are lost, (3) Signers refuse to sign. \
                            Without timeout/expiry, transaction proposals remain pending forever. Implement deadline: \
                            require(block.timestamp < proposalTime + TIMEOUT) or cancellation mechanism.",
                            pc
                        ),
                        confidence: 0.75,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_permanent_signature_storage(&self) -> Vec<MultisigVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_signature_store = false;
        let mut has_signature_clear = false;

        // First pass: find SSTORE operations (storing signatures)
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0x55 { // SSTORE
                has_signature_store = true;
                break;
            }
            pc += 1;
        }

        if !has_signature_store {
            return vulns;
        }

        // Second pass: check for DELETE/clear operation (SSTORE 0)
        pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for pattern: PUSH 0, then SSTORE (deleting storage)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x00 {
                let window_end = (pc + 10).min(self.bytecode.len());
                if self.bytecode[(pc + 2)..window_end].iter().any(|&b| b == 0x55) {
                    has_signature_clear = true;
                    break;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        if has_signature_store && !has_signature_clear {
            vulns.push(MultisigVulnerability {
                pc: 0,
                vulnerability_type: "PermanentSignatureStorage".to_string(),
                description: "Signatures stored in contract without clear/reset mechanism. Issues: \
                    (1) Signatures accumulate permanently, (2) Cannot reuse proposal IDs, \
                    (3) Storage bloat and increased gas costs, (4) Stale signatures may be replayed. \
                    Implement signature clearing after execution or timeout.".to_string(),
                confidence: 0.70,
            });
        }

        vulns
    }

    fn detect_no_cancellation(&self) -> Vec<MultisigVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_execution = false;
        let mut has_revert_path = false;

        // Look for CALL operations (execution)
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0xF1 || self.bytecode[pc] == 0xF4 { // CALL or DELEGATECALL
                has_execution = true;
                
                // Check if REVERT exists in function (cancellation path)
                let window_start = if pc > 200 { pc - 200 } else { 0 };
                let window_end = (pc + 100).min(self.bytecode.len());
                has_revert_path = self.bytecode[window_start..window_end].iter().any(|&b| b == 0xFD);
                
                if !has_revert_path {
                    vulns.push(MultisigVulnerability {
                        pc,
                        vulnerability_type: "NoCancellationMechanism".to_string(),
                        description: format!(
                            "Execution at PC {} without cancellation path. Multisig proposals cannot be cancelled. \
                            If proposal becomes undesirable (market change, discovered vulnerability, mistake), \
                            signers forced to either execute or wait for timeout. Implement cancellation function \
                            requiring threshold signatures to cancel pending proposals.",
                            pc
                        ),
                        confidence: 0.65,
                    });
                }
                break;
            }
            pc += 1;
        }

        vulns
    }
}
