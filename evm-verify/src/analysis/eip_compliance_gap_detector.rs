use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EipComplianceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EipComplianceGapDetector {
    bytecode: Vec<u8>,
}

impl EipComplianceGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EipComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_erc20_missing_events());
        vulnerabilities.extend(self.detect_eip2612_permit_gaps());
        vulnerabilities.extend(self.detect_erc721_metadata_missing());
        vulnerabilities
    }

    fn detect_erc20_missing_events(&self) -> Vec<EipComplianceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (balance update)
                let window_end = (pc + 60).min(self.bytecode.len());
                let has_event = self.bytecode[pc..window_end].iter().any(|&b| b == 0xA1 || b == 0xA2);
                if !has_event {
                    vulns.push(EipComplianceVulnerability {
                        pc, vulnerability_type: "Erc20MissingEvents".to_string(),
                        description: format!("Balance update at PC {} missing Transfer/Approval event required by ERC-20 specification.", pc),
                        confidence: 0.83,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_eip2612_permit_gaps(&self) -> Vec<EipComplianceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ECRECOVER preparation
                let window_end = (pc + 120).min(self.bytecode.len());
                let has_nonce_check = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                if !has_nonce_check {
                    vulns.push(EipComplianceVulnerability {
                        pc, vulnerability_type: "Eip2612PermitGaps".to_string(),
                        description: format!("Permit signature at PC {} missing nonce validation required by EIP-2612 for replay protection.", pc),
                        confidence: 0.80,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_erc721_metadata_missing(&self) -> Vec<EipComplianceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (NFT mint/transfer)
                let start = if pc > 100 { pc - 100 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2 {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let has_uri_storage = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 2;
                    if !has_uri_storage {
                        vulns.push(EipComplianceVulnerability {
                            pc, vulnerability_type: "Erc721MetadataMissing".to_string(),
                            description: format!("NFT operation at PC {} lacks tokenURI storage violating ERC-721 Metadata extension.", pc),
                            confidence: 0.76,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
