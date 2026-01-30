/// ERC-7401 Parent-Governed NFT Detector
/// Parent NFT controls child NFT governance rights

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7401Vulnerability {
    pub vulnerability_type: Erc7401VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7401VulnerabilityType {
    ParentTransferChildAccess,      // Parent transfer revokes child access
    UnauthorizedGovernanceChange,   // Non-parent changes child governance
    CircularGovernance,             // Child governs parent circular dependency
    GovernanceInheritanceConflict,  // Multiple parents claim governance
    ParentBurnChildOrphan,          // Parent burned, child ungoverned
}

pub struct Erc7401ParentGovernedNftDetector {
    bytecode: Vec<u8>,
}

impl Erc7401ParentGovernedNftDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7401Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Governance change without parent validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut changes_governance = false;
            let mut validates_parent = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { changes_governance = true; }
                if self.bytecode[j] == 0xFA { // STATICCALL (check parent)
                    validates_parent = true;
                }
            }
            
            if changes_governance && !validates_parent {
                vulnerabilities.push(Erc7401Vulnerability {
                    vulnerability_type: Erc7401VulnerabilityType::UnauthorizedGovernanceChange,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Child NFT governance changed without parent validation.".to_string(),
                    exploit_scenario: "1. Parent NFT #1 governs Child NFT #100\n\
                                      2. Child #100 holds governance rights to $10M DAO\n\
                                      3. Attacker calls setGovernor on Child #100\n\
                                      4. No parent ownership validation\n\
                                      5. Attacker becomes governor of Child #100\n\
                                      6. Uses Child #100's DAO voting power\n\
                                      7. Proposes malicious DAO upgrade\n\
                                      8. $10M DAO compromised".to_string(),
                    recommendation: "Validate msg.sender owns parent NFT. Check parent approval. \
                                  Add onlyParentOwner modifier.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
