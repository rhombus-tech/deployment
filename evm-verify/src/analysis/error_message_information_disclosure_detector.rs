use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDisclosure {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
    pub revert_data_size: usize,
}

pub struct ErrorMessageInformationDisclosureDetector {
    bytecode: Vec<u8>,
}

impl ErrorMessageInformationDisclosureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ErrorDisclosure> {
        let mut vulnerabilities = Vec::new();

        // Detect REVERT with data (error messages)
        vulnerabilities.extend(self.detect_revert_with_data());
        
        // Detect multiple different REVERT paths (discriminating errors)
        vulnerabilities.extend(self.detect_discriminating_reverts());
        
        // Detect REVERT after SLOAD (potentially leaking storage values in error)
        vulnerabilities.extend(self.detect_storage_in_errors());

        vulnerabilities
    }

    fn detect_revert_with_data(&self) -> Vec<ErrorDisclosure> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // REVERT opcode (0xFD) with non-zero data size
            if opcode == 0xFD {
                // Check preceding instructions for data size (MSTORE pattern suggests error message)
                let start = if pc > 50 { pc - 50 } else { 0 };
                let has_mstore = self.bytecode[start..pc].iter().any(|&b| b == 0x52); // MSTORE
                let has_push = self.bytecode[start..pc].iter().any(|&b| b >= 0x60 && b <= 0x7F);
                
                if has_mstore && has_push {
                    // Estimate data size based on PUSH operations
                    let mut data_size = 0;
                    for i in start..pc {
                        if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                            data_size = (self.bytecode[i] - 0x5F) as usize;
                        }
                    }
                    
                    vulns.push(ErrorDisclosure {
                        pc,
                        vulnerability_type: "DetailedErrorMessage".to_string(),
                        description: format!(
                            "REVERT with error data at PC {} (estimated size: {} bytes). Error messages are \
                            publicly visible and permanent on blockchain. Detailed error messages can leak: \
                            (1) Internal business logic and validation rules, (2) User-specific information, \
                            (3) Contract state details, (4) Security check implementations. Consider using \
                            error codes or generic messages instead of detailed explanations.",
                            pc, data_size
                        ),
                        confidence: 0.75,
                        revert_data_size: data_size,
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

    fn detect_discriminating_reverts(&self) -> Vec<ErrorDisclosure> {
        let mut vulns = Vec::new();
        let mut revert_locations = Vec::new();
        let mut pc = 0;

        // First pass: collect all REVERT locations
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0xFD {
                revert_locations.push(pc);
            }
            pc += 1;
            if self.bytecode[pc - 1] >= 0x60 && self.bytecode[pc - 1] <= 0x7F {
                pc += (self.bytecode[pc - 1] - 0x5F) as usize;
            }
        }

        // If multiple REVERTs exist, they may discriminate execution paths
        if revert_locations.len() >= 3 {
            vulns.push(ErrorDisclosure {
                pc: revert_locations[0],
                vulnerability_type: "DiscriminatingErrors".to_string(),
                description: format!(
                    "Multiple REVERT locations detected ({} total). Different error paths reveal \
                    which validation check failed, potentially leaking: (1) Access control logic, \
                    (2) Input validation rules, (3) State machine transitions, (4) Business logic flow. \
                    Attackers can use this to map out contract behavior and find edge cases.",
                    revert_locations.len()
                ),
                confidence: 0.70,
                revert_data_size: 0,
            });
        }

        vulns
    }

    fn detect_storage_in_errors(&self) -> Vec<ErrorDisclosure> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SLOAD followed by REVERT (storage value in error message)
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 40).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0xFD { // REVERT
                        vulns.push(ErrorDisclosure {
                            pc,
                            vulnerability_type: "StorageInErrorMessage".to_string(),
                            description: format!(
                                "SLOAD at PC {} followed by REVERT at PC {}. Storage values may be included \
                                in error messages. This can leak private contract state such as: user balances, \
                                internal counters, threshold values, or configuration parameters. Error messages \
                                should use generic codes rather than actual storage values.",
                                pc, check_pc
                            ),
                            confidence: 0.80,
                            revert_data_size: 32,
                        });
                        break;
                    }
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
