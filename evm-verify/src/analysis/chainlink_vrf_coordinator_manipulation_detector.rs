use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainlinkVrfVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ChainlinkVrfCoordinatorManipulationDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkVrfCoordinatorManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ChainlinkVrfVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect external calls without access control (unprotected VRF requests)
        vulnerabilities.extend(self.detect_unprotected_calls());
        
        // Detect SSTORE before external calls in callbacks (reentrancy)
        vulnerabilities.extend(self.detect_callback_reentrancy());
        
        // Detect CALL with GAS opcode (insufficient callback gas)
        vulnerabilities.extend(self.detect_gas_issues());

        vulnerabilities
    }

    fn detect_unprotected_calls(&self) -> Vec<ChainlinkVrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0xF1 || opcode == 0xFA { // CALL or STATICCALL
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_caller = self.bytecode[start..pc].iter().any(|&b| b == 0x33); // CALLER
                let has_eq = self.bytecode[start..pc].iter().any(|&b| b == 0x14); // EQ
                
                if !has_caller || !has_eq {
                    vulns.push(ChainlinkVrfVulnerability {
                        pc,
                        vulnerability_type: "UnprotectedVRFRequest".to_string(),
                        description: format!(
                            "External call at PC {} lacks access control. Anyone can call requestRandomWords(), \
                            draining LINK subscription. Add onlyOwner or role-based access control.",
                            pc
                        ),
                        confidence: 0.70,
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

    fn detect_callback_reentrancy(&self) -> Vec<ChainlinkVrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 { // SSTORE
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_call = self.bytecode[(pc + 1)..window_end].iter()
                    .any(|&b| b == 0xF1 || b == 0xF2 || b == 0xF4);
                
                if has_call {
                    vulns.push(ChainlinkVrfVulnerability {
                        pc,
                        vulnerability_type: "CallbackReentrancy".to_string(),
                        description: format!(
                            "State change at PC {} before external call in callback. VRF fulfillRandomWords() \
                            calls your contract - external calls after create reentrancy risk. Use checks-effects-interactions.",
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

    fn detect_gas_issues(&self) -> Vec<ChainlinkVrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0xF1 { // CALL
                let start = if pc > 30 { pc - 30 } else { 0 };
                let uses_gas = self.bytecode[start..pc].iter().any(|&b| b == 0x5A); // GAS opcode
                
                if uses_gas {
                    vulns.push(ChainlinkVrfVulnerability {
                        pc,
                        vulnerability_type: "InsufficientCallbackGas".to_string(),
                        description: format!(
                            "Call at PC {} uses GAS opcode. Set explicit callbackGasLimit for Chainlink VRF. \
                            Insufficient gas causes callback failure but still consumes LINK.",
                            pc
                        ),
                        confidence: 0.80,
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
}
