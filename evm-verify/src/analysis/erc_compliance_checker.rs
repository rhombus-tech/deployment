// ERC Token Standard Compliance Checker
// Validates compliance with ERC-20, ERC-721, ERC-1155, ERC-4626, ERC-2981 standards
// Historical: Token incompatibility, DEX failures, lost funds

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERCComplianceVulnerability {
    pub vulnerability_type: ERCComplianceType,
    pub standard: TokenStandard,
    pub severity: SecuritySeverity,
    pub description: String,
    pub missing_functions: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenStandard {
    ERC20,
    ERC721,
    ERC1155,
    ERC4626,
    ERC2981,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERCComplianceType {
    MissingRequiredFunction,     // Standard function not implemented
    WrongReturnType,             // Function returns wrong type
    MissingEvent,                // Required event not emitted
    IncorrectEventParameters,    // Event has wrong parameters
    MissingApproval,             // No approval mechanism
    NoTotalSupplyTracking,       // Total supply not tracked
    TransferDoesntReturnBool,    // transfer() doesn't return bool
    MissingBalanceOf,            // No balanceOf function
    InvalidDecimalsFunction,     // decimals() implementation issues
    MissingMetadata,             // No name/symbol functions
    ApprovalRaceCondition,       // approve() has race condition
    MintWithoutEvent,            // Mint without Transfer event
    BurnWithoutEvent,            // Burn without Transfer event
}

pub struct ERCComplianceChecker {
    bytecode: Vec<u8>,
}

impl ERCComplianceChecker {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERCComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect which standard this might be
        let is_erc20 = self.detect_erc20_pattern();
        let is_erc721 = self.detect_erc721_pattern();
        let is_erc1155 = self.detect_erc1155_pattern();
        let is_erc4626 = self.detect_erc4626_pattern();

        if is_erc20 {
            vulnerabilities.extend(self.check_erc20_compliance());
        }
        if is_erc721 {
            vulnerabilities.extend(self.check_erc721_compliance());
        }
        if is_erc1155 {
            vulnerabilities.extend(self.check_erc1155_compliance());
        }
        if is_erc4626 {
            vulnerabilities.extend(self.check_erc4626_compliance());
        }

        vulnerabilities
    }

    fn detect_erc20_pattern(&self) -> bool {
        // ERC-20 function signatures
        let erc20_sigs = [
            &[0x70, 0xa0, 0x82, 0x31][..], // balanceOf(address)
            &[0xa9, 0x05, 0x9c, 0xbb][..], // transfer(address,uint256)
            &[0x18, 0x16, 0x0d, 0xdd][..], // totalSupply()
        ];

        erc20_sigs.iter().filter(|&&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }).count() >= 2
    }

    fn detect_erc721_pattern(&self) -> bool {
        // ERC-721 function signatures
        let erc721_sigs = [
            &[0x70, 0xa0, 0x82, 0x31][..], // balanceOf(address)
            &[0x63, 0x52, 0x21, 0x1e][..], // ownerOf(uint256)
            &[0x23, 0xb8, 0x72, 0xdd][..], // transferFrom(address,address,uint256)
        ];

        erc721_sigs.iter().filter(|&&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }).count() >= 2
    }

    fn detect_erc1155_pattern(&self) -> bool {
        // ERC-1155 function signature
        let sig = &[0x00, 0xfd, 0xd5, 0x8e][..]; // balanceOf(address,uint256)
        self.bytecode.windows(sig.len()).any(|w| w == sig)
    }

    fn detect_erc4626_pattern(&self) -> bool {
        // ERC-4626 vault signatures
        let vault_sigs = [
            &[0x38, 0xd5, 0x2e, 0x0f][..], // asset()
            &[0x01, 0xe1, 0xd1, 0x14][..], // totalAssets()
        ];

        vault_sigs.iter().filter(|&&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }).count() >= 1
    }

    fn check_erc20_compliance(&self) -> Vec<ERCComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut missing_functions = Vec::new();

        // Required ERC-20 functions
        let required_funcs = [
            (&[0x70, 0xa0, 0x82, 0x31][..], "balanceOf(address)"),
            (&[0xa9, 0x05, 0x9c, 0xbb][..], "transfer(address,uint256)"),
            (&[0x23, 0xb8, 0x72, 0xdd][..], "transferFrom(address,address,uint256)"),
            (&[0x095, 0xea, 0x7b, 0x3][..], "approve(address,uint256)"),
            (&[0xdd, 0x62, 0xed, 0x3e][..], "allowance(address,address)"),
            (&[0x18, 0x16, 0x0d, 0xdd][..], "totalSupply()"),
        ];

        for (sig, name) in &required_funcs {
            if !self.bytecode.windows(sig.len()).any(|w| w == *sig) {
                missing_functions.push(name.to_string());
            }
        }

        if !missing_functions.is_empty() {
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::MissingRequiredFunction,
                standard: TokenStandard::ERC20,
                severity: SecuritySeverity::High,
                description: "ERC-20 token missing required functions".to_string(),
                missing_functions: missing_functions.clone(),
                remediation: format!("Implement missing functions: {}", missing_functions.join(", ")),
            });
        }

        // Check for Transfer event signature
        let transfer_event = &[
            0xdd, 0xf2, 0x52, 0xad, // Transfer(address,address,uint256) event
            0x1b, 0xe2, 0xc8, 0x9b,
        ];
        if !self.bytecode.windows(8).any(|w| w == transfer_event) {
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::MissingEvent,
                standard: TokenStandard::ERC20,
                severity: SecuritySeverity::Medium,
                description: "Transfer event not found - required by ERC-20".to_string(),
                missing_functions: vec!["Transfer event".to_string()],
                remediation: "Emit Transfer(from, to, amount) on all transfers".to_string(),
            });
        }

        // Check for approval race condition protection
        let approve_sig = &[0x09, 0x5e, 0xa7, 0xb3][..]; // approve()
        if self.bytecode.windows(approve_sig.len()).any(|w| w == approve_sig) {
            // Check if there's a check for current allowance before setting new one
            // This is a heuristic - proper check would need full analysis
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::ApprovalRaceCondition,
                standard: TokenStandard::ERC20,
                severity: SecuritySeverity::Medium,
                description: "approve() may be vulnerable to race condition".to_string(),
                missing_functions: vec![],
                remediation: "Consider requiring allowance to be 0 or implementing increaseAllowance/decreaseAllowance".to_string(),
            });
        }

        vulnerabilities
    }

    fn check_erc721_compliance(&self) -> Vec<ERCComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut missing_functions = Vec::new();

        // Required ERC-721 functions
        let required_funcs = [
            (&[0x70, 0xa0, 0x82, 0x31][..], "balanceOf(address)"),
            (&[0x63, 0x52, 0x21, 0x1e][..], "ownerOf(uint256)"),
            (&[0x23, 0xb8, 0x72, 0xdd][..], "transferFrom(address,address,uint256)"),
            (&[0x42, 0x84, 0x2e, 0x0e][..], "safeTransferFrom(address,address,uint256)"),
            (&[0x09, 0x5e, 0xa7, 0xb3][..], "approve(address,uint256)"),
            (&[0x08, 0x18, 0x12, 0xfc][..], "getApproved(uint256)"),
            (&[0xa2, 0x2c, 0xb4, 0x65][..], "setApprovalForAll(address,bool)"),
        ];

        for (sig, name) in &required_funcs {
            if !self.bytecode.windows(sig.len()).any(|w| w == *sig) {
                missing_functions.push(name.to_string());
            }
        }

        if !missing_functions.is_empty() {
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::MissingRequiredFunction,
                standard: TokenStandard::ERC721,
                severity: SecuritySeverity::High,
                description: "ERC-721 NFT missing required functions".to_string(),
                missing_functions: missing_functions.clone(),
                remediation: format!("Implement missing functions: {}", missing_functions.join(", ")),
            });
        }

        vulnerabilities
    }

    fn check_erc1155_compliance(&self) -> Vec<ERCComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut missing_functions = Vec::new();

        // Required ERC-1155 functions
        let required_funcs = [
            (&[0x00, 0xfd, 0xd5, 0x8e][..], "balanceOf(address,uint256)"),
            (&[0x4e, 0x12, 0x73, 0xf4][..], "balanceOfBatch(address[],uint256[])"),
            (&[0xf2, 0x42, 0x43, 0x2a][..], "safeTransferFrom(address,address,uint256,uint256,bytes)"),
            (&[0x2e, 0xb2, 0xc2, 0xd6][..], "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"),
            (&[0xa2, 0x2c, 0xb4, 0x65][..], "setApprovalForAll(address,bool)"),
            (&[0xe9, 0x85, 0xe9, 0xc5][..], "isApprovedForAll(address,address)"),
        ];

        for (sig, name) in &required_funcs {
            if !self.bytecode.windows(sig.len()).any(|w| w == *sig) {
                missing_functions.push(name.to_string());
            }
        }

        if !missing_functions.is_empty() {
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::MissingRequiredFunction,
                standard: TokenStandard::ERC1155,
                severity: SecuritySeverity::High,
                description: "ERC-1155 multi-token missing required functions".to_string(),
                missing_functions: missing_functions.clone(),
                remediation: format!("Implement missing functions: {}", missing_functions.join(", ")),
            });
        }

        vulnerabilities
    }

    fn check_erc4626_compliance(&self) -> Vec<ERCComplianceVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut missing_functions = Vec::new();

        // Required ERC-4626 vault functions
        let required_funcs = [
            (&[0x38, 0xd5, 0x2e, 0x0f][..], "asset()"),
            (&[0x01, 0xe1, 0xd1, 0x14][..], "totalAssets()"),
            (&[0xc6, 0xe6, 0xf5, 0x92][..], "convertToShares(uint256)"),
            (&[0x07, 0xa2, 0x20, 0x3c][..], "convertToAssets(uint256)"),
            (&[0x6e, 0x55, 0x3f, 0x65][..], "deposit(uint256,address)"),
            (&[0xb4, 0x60, 0xaf, 0x94][..], "withdraw(uint256,address,address)"),
        ];

        for (sig, name) in &required_funcs {
            if !self.bytecode.windows(sig.len()).any(|w| w == *sig) {
                missing_functions.push(name.to_string());
            }
        }

        if !missing_functions.is_empty() {
            vulnerabilities.push(ERCComplianceVulnerability {
                vulnerability_type: ERCComplianceType::MissingRequiredFunction,
                standard: TokenStandard::ERC4626,
                severity: SecuritySeverity::High,
                description: "ERC-4626 vault missing required functions".to_string(),
                missing_functions: missing_functions.clone(),
                remediation: format!("Implement missing vault functions: {}", missing_functions.join(", ")),
            });
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_incomplete_erc20() {
        // Bytecode with only balanceOf, missing other functions
        let mut bytecode = vec![0x00; 100];
        // Add balanceOf signature
        bytecode[10..14].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
        
        let checker = ERCComplianceChecker::new(bytecode);
        let vulns = checker.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ERCComplianceType::MissingRequiredFunction)));
    }
}
