/// ERC-2771 Meta-Transaction Forwarder Detector
/// Gasless transactions via trusted forwarder

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc2771Vulnerability {
    pub vulnerability_type: Erc2771VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc2771VulnerabilityType {
    UntrustedForwarder,             // Accepts any forwarder
    MsgSenderNotExtracted,          // Uses msg.sender instead of _msgSender()
    ForwarderValidationMissing,     // No isTrustedForwarder check
    NonceReplayVulnerable,          // Nonce not validated
    SignatureNotVerified,           // Forwarder signature not checked
}

pub struct Erc2771MetaTransactionDetector {
    bytecode: Vec<u8>,
}

impl Erc2771MetaTransactionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc2771Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Uses msg.sender without checking forwarder
        for i in 0..self.bytecode.len().saturating_sub(10) {
            let mut uses_msg_sender = false;
            let mut validates_forwarder = false;
            
            for j in i..self.bytecode.len().min(i + 10) {
                if self.bytecode[j] == 0x33 { // CALLER (msg.sender)
                    uses_msg_sender = true;
                }
                if self.bytecode[j] == 0x54 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // SLOAD EQ (forwarder check)
                    validates_forwarder = true;
                }
            }
            
            if uses_msg_sender && !validates_forwarder {
                vulnerabilities.push(Erc2771Vulnerability {
                    vulnerability_type: Erc2771VulnerabilityType::MsgSenderNotExtracted,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Uses msg.sender directly without extracting real sender from calldata.".to_string(),
                    exploit_scenario: "1. Alice wants gasless NFT transfer\n\
                                      2. Alice signs meta-transaction\n\
                                      3. Relayer forwards to contract\n\
                                      4. Contract uses msg.sender = relayer address\n\
                                      5. Access control checks relayer, not Alice\n\
                                      6. Alice's signature bypassed\n\
                                      7. Relayer steals Alice's NFT\n\
                                      8. $100K NFT lost via meta-transaction exploit".to_string(),
                    recommendation: "Use _msgSender() that extracts sender from calldata. \
                                  Validate trusted forwarder. Check last 20 bytes of calldata for real sender.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
