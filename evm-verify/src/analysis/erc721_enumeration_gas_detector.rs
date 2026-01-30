/// ERC-721 Enumeration Gas Bomb Detector
///
/// Detects O(n²) complexity attacks via ERC-721Enumerable tokenOfOwnerByIndex.
/// Enumerating all tokens owned by an address can cause gas bombs.
///
/// Why dangerous:
/// - tokenOfOwnerByIndex iterates to find nth token
/// - Getting all tokens = O(n²) complexity
/// - Used in loops → gas explosion
/// - DoS marketplaces, indexers, frontends
///
/// Real issues:
/// - OpenSea indexing failures
/// - Marketplace UI freezes
/// - $1M+ in unusable contracts
///
/// Example:
/// ```solidity
/// function getAll(address owner) external view returns (uint256[] memory) {
///     uint256 balance = nft.balanceOf(owner);
///     uint256[] memory tokens = new uint256[](balance);
///     for (uint i = 0; i < balance; i++) {
///         tokens[i] = nft.tokenOfOwnerByIndex(owner, i); // O(n) each
///     }
///     return tokens; // Total O(n²) - GAS BOMB!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC721EnumerationVulnerability {
    pub vulnerability_type: ERC721EnumerationIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC721EnumerationIssueType {
    TokenOfOwnerByIndexInLoop,     // O(n²) enumeration
    UnboundedEnumeration,          // Enumerating all tokens
    BalanceOfInLoop,               // Repeated balance checks
}

pub struct ERC721EnumerationGasDetector {
    bytecode: Vec<u8>,
}

impl ERC721EnumerationGasDetector {
    const TOKEN_OF_OWNER_BY_INDEX: [u8; 4] = [0x2f, 0x74, 0x5c, 0x59];
    const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERC721EnumerationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if &self.bytecode[i..i+4] == &Self::TOKEN_OF_OWNER_BY_INDEX {
                vulnerabilities.push(ERC721EnumerationVulnerability {
                    vulnerability_type: ERC721EnumerationIssueType::TokenOfOwnerByIndexInLoop,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: "tokenOfOwnerByIndex detected - O(n²) gas risk if in loop".to_string(),
                    exploit_scenario: "ERC-721 Enumeration Gas Bomb: Using tokenOfOwnerByIndex in loop creates O(n²) complexity. Limit iterations or use alternative storage pattern.".to_string(),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
