/// ERC-1271 Contract Signature Validation Detector
/// Smart contracts can validate signatures (Gnosis Safe, AA wallets)

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc1271Vulnerability {
    pub vulnerability_type: Erc1271VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc1271VulnerabilityType {
    MagicValueNotValidated,         // Doesn't check 0x1626ba7e return
    SignatureReplayAcrossContracts, // Signature valid on multiple contracts
    InvalidSignatureAccepted,       // Accepts bad signatures
    IsValidSignatureNotImplemented, // Missing ERC-1271 implementation
    EOAAssumedForContracts,         // ecrecover used instead of ERC-1271
}

pub struct Erc1271ContractSignatureDetector {
    bytecode: Vec<u8>,
}

impl Erc1271ContractSignatureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc1271Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: ecrecover without ERC-1271 fallback
        for i in 0..self.bytecode.len().saturating_sub(10) {
            let mut uses_ecrecover = false;
            let mut checks_erc1271 = false;
            
            for j in i..self.bytecode.len().min(i + 10) {
                if self.bytecode[j] == 0x01 { // Precompile 1 (ecrecover)
                    uses_ecrecover = true;
                }
                if self.bytecode[j] == 0xFA { // STATICCALL (ERC-1271 check)
                    checks_erc1271 = true;
                }
            }
            
            if uses_ecrecover && !checks_erc1271 {
                vulnerabilities.push(Erc1271Vulnerability {
                    vulnerability_type: Erc1271VulnerabilityType::EOAAssumedForContracts,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Uses ecrecover only, doesn't support contract signatures (ERC-1271).".to_string(),
                    exploit_scenario: "1. Gnosis Safe multisig owns NFT\n\
                                      2. Safe tries to list NFT on marketplace\n\
                                      3. Marketplace uses ecrecover for signature validation\n\
                                      4. Safe signature validation fails (not EOA)\n\
                                      5. $50K NFT cannot be listed/traded\n\
                                      6. All AA wallet users excluded".to_string(),
                    recommendation: "Implement ERC-1271 support. Check if address is contract. \
                                  Call isValidSignature(hash, signature) for contracts.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
