/// ERC-6551 Token Bound Accounts Detector
/// NFT-owned smart contract accounts

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc6551Vulnerability {
    pub vulnerability_type: Erc6551VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc6551VulnerabilityType {
    UnprotectedAccountCreation,     // Anyone can create account for any NFT
    OwnershipTransferExploit,       // NFT transfer doesn't secure account assets
    ExecuteCallbackReentrancy,      // executeCall reentrancy
    MissingNFTOwnershipValidation,  // Account operations without NFT owner check
    AccountImplementationUpgrade,   // Malicious implementation upgrade
    CrossChainOwnershipDesync,      // NFT on L1, account on L2 desync
    RecursiveAccountOwnership,      // Account owns NFT that owns account
}

pub struct Erc6551TokenBoundAccountsDetector {
    bytecode: Vec<u8>,
}

impl Erc6551TokenBoundAccountsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc6551Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Account creation without validation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut creates_account = false;
            let mut validates_caller = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0xF0 || self.bytecode[j] == 0xF5 { // CREATE/CREATE2
                    creates_account = true;
                }
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        validates_caller = true;
                    }
                }
            }
            
            if creates_account && !validates_caller {
                vulnerabilities.push(Erc6551Vulnerability {
                    vulnerability_type: Erc6551VulnerabilityType::UnprotectedAccountCreation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "ERC-6551 token bound account created without access control.".to_string(),
                    exploit_scenario: "1. Attacker observes valuable NFT #123\n\
                                      2. Calls createAccount(nft, 123) before owner\n\
                                      3. Account created with attacker-controlled parameters\n\
                                      4. Owner transfers NFT, assumes account secure\n\
                                      5. Attacker front-runs operations on compromised account\n\
                                      6. $500K in assets stolen from token bound account".to_string(),
                    recommendation: "Validate caller or add initialization protection. Use ERC-6551 registry. \
                                  Ensure only NFT owner can initialize account.".to_string(),
                });
            }
        }
        
        // Pattern: executeCall without NFT ownership check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut executes_call = false;
            let mut checks_nft_owner = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xF4 { // CALL/DELEGATECALL
                    executes_call = true;
                }
                if self.bytecode[j] == 0xFA { // STATICCALL (to check NFT owner)
                    checks_nft_owner = true;
                }
            }
            
            if executes_call && !checks_nft_owner {
                vulnerabilities.push(Erc6551Vulnerability {
                    vulnerability_type: Erc6551VulnerabilityType::MissingNFTOwnershipValidation,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Account executeCall without verifying NFT ownership.".to_string(),
                    exploit_scenario: "1. Alice owns NFT #1 with token bound account TBA1\n\
                                      2. Alice stores 100 ETH in TBA1\n\
                                      3. Alice sells NFT #1 to Bob\n\
                                      4. Bob becomes new owner\n\
                                      5. Alice calls TBA1.executeCall() before ownership check updates\n\
                                      6. Alice drains 100 ETH from account she no longer owns\n\
                                      7. Bob buys empty account, loses $200K".to_string(),
                    recommendation: "Always verify msg.sender == ownerOf(tokenId) before executeCall. \
                                  Cache ownership validation. Add reentrancy guard.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unprotected_creation() {
        let bytecode = vec![
            0xF5, // CREATE2 (no validation)
        ];
        
        let detector = Erc6551TokenBoundAccountsDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc6551VulnerabilityType::UnprotectedAccountCreation
        )));
    }
}
