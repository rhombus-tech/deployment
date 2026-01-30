use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BeanstalkGovernanceVulnerability {
    FlashLoanVotingPower { description: String, location: usize, confidence: f32 },
    NoSnapshotVoting { description: String, location: usize, confidence: f32 },
    MissingTimeWeighting { description: String, location: usize, confidence: f32 },
    InstantProposalExecution { description: String, location: usize, confidence: f32 },
}

pub struct BeanstalkFlashLoanGovernanceDetector {
    bytecode: Vec<u8>,
}

impl BeanstalkFlashLoanGovernanceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BeanstalkGovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_flash_loan_voting());
        vulnerabilities.extend(self.detect_no_snapshot());
        vulnerabilities.extend(self.detect_instant_execution());
        vulnerabilities
    }
    
    fn detect_flash_loan_voting(&self) -> Vec<BeanstalkGovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let vote_sigs = [&[0x15, 0x37, 0x3e, 0x3d][..], &[0xb6, 0x1d, 0x27, 0xf6][..]];
        for sig in &vote_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 200, self.bytecode.len())];
                    let reads_current_balance = section.contains(&0x54) && section.windows(4).any(|w| w == &[0x70, 0xa0, 0x82, 0x31]);
                    let has_historical_check = section.windows(8).any(|w| w.contains(&0x42) && w.contains(&0x03));
                    if reads_current_balance && !has_historical_check {
                        vulnerabilities.push(BeanstalkGovernanceVulnerability::FlashLoanVotingPower {
                            description: format!("Vote function at PC {} uses current token balance for voting power. Beanstalk exploit: attacker flash loaned $1B in tokens → voted → executed malicious proposal → drained $180M. Must use snapshot-based voting.", i),
                            location: i,
                            confidence: 0.94,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_no_snapshot(&self) -> Vec<BeanstalkGovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_balance_check = section.windows(4).any(|w| w == &[0x70, 0xa0, 0x82, 0x31]);
                let has_snapshot_sig = section.windows(4).any(|w| w == &[0x43, 0x87, 0xa5, 0xec] || w == &[0x4e, 0xe2, 0xcd, 0x7e]);
                if has_balance_check && !has_snapshot_sig {
                    vulnerabilities.push(BeanstalkGovernanceVulnerability::NoSnapshotVoting {
                        description: format!("Governance at PC {} lacks snapshot mechanism. Should record balances at proposal creation block, not check current balances. Prevents flash loan attacks.", i),
                        location: i,
                        confidence: 0.89,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_instant_execution(&self) -> Vec<BeanstalkGovernanceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let execute_sigs = [&[0xfe, 0x9d, 0x93, 0x03][..], &[0x2c, 0x4e, 0x5a, 0x69][..]];
        for sig in &execute_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 150, self.bytecode.len())];
                    let has_timelock = section.contains(&0x42) && section.contains(&0x01) && section.contains(&0x10);
                    if !has_timelock {
                        vulnerabilities.push(BeanstalkGovernanceVulnerability::InstantProposalExecution {
                            description: format!("Proposal execution at PC {} has no timelock. Beanstalk: proposal passed and executed in same block. Add minimum 24-48h delay between vote passage and execution.", i),
                            location: i,
                            confidence: 0.91,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
}
