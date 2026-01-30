use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataSchemaVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MetadataJsonSchemaViolationDetector {
    bytecode: Vec<u8>,
}

impl MetadataJsonSchemaViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MetadataSchemaVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unvalidated_metadata_storage());
        vulnerabilities.extend(self.detect_missing_schema_enforcement());
        vulnerabilities.extend(self.detect_dynamic_metadata_injection());

        vulnerabilities
    }

    fn detect_unvalidated_metadata_storage(&self) -> Vec<MetadataSchemaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE operations for metadata updates
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for string/URI data (CALLDATALOAD, CALLDATACOPY patterns)
                let has_calldata = window.iter().any(|&b| matches!(b, 0x35 | 0x37)); // CALLDATALOAD, CALLDATACOPY
                
                // Missing validation (no EQ, LT checks for length/format)
                let has_length_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_format_check = window.iter().any(|&b| b == 0x14); // EQ (for prefix/format checks)
                
                if has_calldata && !has_length_check && !has_format_check {
                    vulns.push(MetadataSchemaVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedMetadataStorage".to_string(),
                        description: format!(
                            "Metadata stored at PC {} without schema validation. Missing checks for: \
                            JSON structure validity, required field presence, data type constraints, \
                            and maximum length limits. Attacker can inject malformed metadata causing \
                            display issues, parsing errors, or exploit vulnerabilities in metadata consumers.",
                            pc
                        ),
                        confidence: 0.86,
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

    fn detect_missing_schema_enforcement(&self) -> Vec<MetadataSchemaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External calls that might update metadata URIs
            if matches!(opcode, 0xF1 | 0xFA) {
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut has_revert_path = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 50 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                    }
                    
                    if matches!(check_op, 0xFD | 0x57) { // REVERT, JUMPI (conditional revert)
                        has_revert_path = true;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && opcode <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !has_revert_path {
                    vulns.push(MetadataSchemaVulnerability {
                        pc,
                        vulnerability_type: "MissingSchemaEnforcement".to_string(),
                        description: format!(
                            "Metadata update at PC {} without schema enforcement. Missing validation for: \
                            ERC-721/1155 metadata standards compliance, OpenSea metadata requirements, \
                            attribute type validation, and trait rarity constraints. Non-conforming metadata \
                            breaks marketplace compatibility and NFT functionality.",
                            pc
                        ),
                        confidence: 0.84,
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

    fn detect_dynamic_metadata_injection(&self) -> Vec<MetadataSchemaVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // MSTORE/MSTORE8 operations that build strings dynamically
            if matches!(opcode, 0x52 | 0x53) { // MSTORE, MSTORE8
                let start = if pc > 50 { pc - 50 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for user input (CALLDATALOAD)
                let has_user_input = window.iter().any(|&b| b == 0x35);
                
                // Check for string concatenation patterns (multiple MSTORE operations)
                let end = (pc + 50).min(self.bytecode.len());
                let forward_window = &self.bytecode[pc..end];
                let mstore_count = forward_window.iter().filter(|&&b| matches!(b, 0x52 | 0x53)).count();
                
                if has_user_input && mstore_count > 2 {
                    vulns.push(MetadataSchemaVulnerability {
                        pc,
                        vulnerability_type: "DynamicMetadataInjection".to_string(),
                        description: format!(
                            "Dynamic metadata construction at PC {} using unvalidated user input. \
                            Vulnerable to: HTML/JavaScript injection in metadata, URI manipulation, \
                            SVG injection attacks, and cross-site scripting (XSS) when metadata is \
                            rendered by marketplaces. Missing input sanitization and content security policies.",
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
}
