use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsCidVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct IpfsCidManipulationDetector {
    bytecode: Vec<u8>,
}

impl IpfsCidManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<IpfsCidVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_cid_storage());
        vulnerabilities.extend(self.detect_cid_validation_bypass());
        vulnerabilities.extend(self.detect_cid_prefix_confusion());

        vulnerabilities
    }

    fn detect_unchecked_cid_storage(&self) -> Vec<IpfsCidVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE without preceding validation checks
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for CID-like data (32-byte hash patterns)
                let has_hash_data = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x20); // PUSH1 32
                
                // Missing validation (no EQ, LT, GT checks)
                let has_validation = window.iter().any(|&b| matches!(b, 0x14 | 0x10 | 0x11 | 0x12 | 0x13)); // EQ, LT, GT, SLT, SGT
                
                if has_hash_data && !has_validation {
                    vulns.push(IpfsCidVulnerability {
                        pc,
                        vulnerability_type: "UncheckedCIDStorage".to_string(),
                        description: format!(
                            "IPFS CID stored at PC {} without validation. Attacker can store arbitrary CIDs \
                            pointing to malicious content, replaced metadata, or non-existent data. \
                            Missing hash format validation and content verification.",
                            pc
                        ),
                        confidence: 0.88,
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

    fn detect_cid_validation_bypass(&self) -> Vec<IpfsCidVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call followed by CID update without checking return value
            if matches!(opcode, 0xF1 | 0xFA) { // CALL, STATICCALL
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut checked_return = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 50 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                        break;
                    }
                    
                    // Check if return value is validated
                    if matches!(check_op, 0x15 | 0x16) { // ISZERO, NOT (checking boolean return)
                        checked_return = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !checked_return {
                    vulns.push(IpfsCidVulnerability {
                        pc,
                        vulnerability_type: "CIDValidationBypass".to_string(),
                        description: format!(
                            "CID validation call at PC {} followed by storage without return check. \
                            Failed IPFS gateway calls or CID verification can be silently ignored, \
                            allowing invalid CIDs to be stored and referenced.",
                            pc
                        ),
                        confidence: 0.85,
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

    fn detect_cid_prefix_confusion(&self) -> Vec<IpfsCidVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for byte slicing operations on potential CIDs
            if opcode == 0x1A { // BYTE
                let start = if pc > 30 { pc - 30 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for CID prefix handling (multibase/multicodec prefixes)
                let has_prefix_check = window.windows(3).any(|w| {
                    w[0] == 0x60 && matches!(w[1], 0x00..=0x02) // PUSH1 with small values (0,1,2 for CID versions)
                });
                
                // Check if there's proper version validation
                let has_version_validation = window.iter().any(|&b| b == 0x14); // EQ check
                
                if has_prefix_check && !has_version_validation {
                    vulns.push(IpfsCidVulnerability {
                        pc,
                        vulnerability_type: "CIDPrefixConfusion".to_string(),
                        description: format!(
                            "CID prefix extraction at PC {} without version validation. \
                            CIDv0 (Qm...) vs CIDv1 (b...) confusion can lead to incorrect content addressing, \
                            multibase encoding issues, or compatibility problems with IPFS gateways.",
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
