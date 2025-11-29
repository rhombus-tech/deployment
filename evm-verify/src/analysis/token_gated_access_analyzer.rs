/// Token-Gated Access Control Vulnerability Analyzer
/// Targets: NFT-gated features, token balance requirements

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGatedVulnerability {
    pub vulnerability_type: TokenGatedVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenGatedVulnType {
    NFTOwnershipBypass,
    TokenBalanceFlashLoan,
    StakingRequirementCircumvention,
    MembershipNFTExploit,
}

pub struct TokenGatedAccessAnalyzer {
    bytecode: Vec<u8>,
}

impl TokenGatedAccessAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TokenGatedVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_token_gated() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_nft_ownership_bypass());
        vulnerabilities.extend(self.detect_flash_loan_bypass());

        vulnerabilities
    }

    fn is_token_gated(&self) -> bool {
        let gating_sigs = [
            &[0x70, 0xa0, 0x82, 0x31][..], // balanceOf()
            &[0x63, 0x52, 0x21, 0x1e][..], // ownerOf()
        ];

        gating_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_nft_ownership_bypass(&self) -> Vec<TokenGatedVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0xFA { // STATICCALL (balanceOf/ownerOf)
                let single_check = !self.bytecode[i+1..i+50]
                    .windows(1).any(|w| w[0] == 0x42); // No TIMESTAMP (no holding period)

                if single_check {
                    vulnerabilities.push(TokenGatedVulnerability {
                        vulnerability_type: TokenGatedVulnType::NFTOwnershipBypass,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "NFT ownership check without holding period requirement".to_string(),
                        exploit_scenario: "NFT Flash Ownership:\n\
                            1. Feature requires owning specific NFT\n\
                            2. No holding period check\n\
                            3. Attacker flash loans NFT\n\
                            4. Accesses gated feature\n\
                            5. Returns NFT\n\
                            6. Bypassed access control\n\
                            \n\
                            Impact: Token-gating ineffective".to_string(),
                        remediation: "Require minimum holding period (1+ blocks)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_flash_loan_bypass(&self) -> Vec<TokenGatedVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x11 { // GT (balance > threshold)
                let no_time_weight = !self.bytecode[i.saturating_sub(50)..i+50]
                    .windows(1).any(|w| w[0] == 0x42); // No TIMESTAMP

                if no_time_weight {
                    vulnerabilities.push(TokenGatedVulnerability {
                        vulnerability_type: TokenGatedVulnType::TokenBalanceFlashLoan,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Token balance gating without time-weighted checks".to_string(),
                        exploit_scenario: "Flash Loan Balance Bypass:\n\
                            1. Feature requires 10,000 token balance\n\
                            2. No time-weighted average\n\
                            3. Attacker flash loans 10,000 tokens\n\
                            4. Passes balance check\n\
                            5. Accesses feature\n\
                            6. Returns tokens\n\
                            \n\
                            Impact: Balance requirements bypassable".to_string(),
                        remediation: "Use time-weighted average balance (TWAB)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}
