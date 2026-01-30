/// ERC-404 (Pandora) Semi-Fungible Token Detector
///
/// Detects vulnerabilities in the experimental ERC-404 standard which combines
/// ERC-20 and ERC-721 functionality. This creates unique attack surfaces around
/// the automatic NFT minting/burning on token transfers.
///
/// Real-world context:
/// - Pandora launched Feb 2024, reached $250M market cap
/// - DN-404 improved implementation (April 2024)
/// - Key risk: Reentrancy during automatic NFT mint/burn
/// - Exploit potential: $50M+ if widely adopted

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc404Vulnerability {
    pub vulnerability_type: Erc404VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc404VulnerabilityType {
    ReentrancyDuringNftMint,      // Callback during automatic NFT minting
    ReentrancyDuringNftBurn,      // Callback during automatic NFT burning
    InconsistentState,            // ERC20 balance != NFT ownership
    MintBurnLoopDos,              // Expensive loop during transfers
    TransferHookManipulation,     // Malicious beforeTransfer/afterTransfer
    OwnedIndexOutOfBounds,        // Array bounds in owned[] tracking
    DoubleEntryAccounting,        // Balance counted in both ERC20 and NFT
    WhitelistBypass,              // Bypass ERC721 restrictions via ERC20
}

pub struct Erc404Detector {
    bytecode: Vec<u8>,
}

impl Erc404Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc404Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Detect reentrancy during automatic NFT operations
        if let Some(vuln) = self.detect_nft_operation_reentrancy() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Detect inconsistent state between ERC20 and ERC721
        if let Some(vuln) = self.detect_state_inconsistency() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Detect expensive loops during transfers
        if let Some(vuln) = self.detect_mint_burn_loop_dos() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Detect transfer hook manipulation
        if let Some(vuln) = self.detect_transfer_hook_risks() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Detect array bounds issues in owned[] tracking
        if let Some(vuln) = self.detect_owned_array_bounds() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_nft_operation_reentrancy(&self) -> Option<Erc404Vulnerability> {
        // Pattern: Transfer → _mintNFT → CALL (to recipient) → State change after
        // ERC404 transfers trigger automatic NFT mints/burns which call receiver
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for: CALL followed by SSTORE (state change after external call)
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA { // CALL or STATICCALL
                // Check if SSTORE happens within next 20 opcodes
                for j in (i+1)..self.bytecode.len().min(i + 20) {
                    if self.bytecode[j] == 0x55 { // SSTORE after CALL
                        return Some(Erc404Vulnerability {
                            vulnerability_type: Erc404VulnerabilityType::ReentrancyDuringNftMint,
                            severity: "Critical".to_string(),
                            location: vec![i, j],
                            description: "ERC-404 transfers trigger automatic NFT minting which performs \
                                        external calls before completing state updates. Attacker can reenter \
                                        during onERC721Received callback.".to_string(),
                            exploit_scenario: "1. Attacker receives ERC-404 tokens\n\
                                              2. Automatic NFT mint triggers onERC721Received\n\
                                              3. Attacker reenters via transfer() in callback\n\
                                              4. Manipulates state before original transfer completes\n\
                                              5. Result: Double-mint NFTs or drain balances".to_string(),
                            recommendation: "Use reentrancy guard on all transfer functions. Apply \
                                          checks-effects-interactions pattern. Update all state before \
                                          calling _mintNFT or _burnNFT.".to_string(),
                        });
                    }
                }
            }
        }
        
        None
    }
    
    fn detect_state_inconsistency(&self) -> Option<Erc404Vulnerability> {
        // ERC-404 must keep ERC20 balanceOf and NFT ownership in sync
        // Look for: balance update without corresponding NFT operation
        
        let mut has_balance_update = false;
        let mut has_nft_operation = false;
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            // SSTORE to balance mapping
            if self.bytecode[i] == 0x55 { // SSTORE
                has_balance_update = true;
            }
            
            // NFT operation signatures: _mint, _burn (function selectors)
            if i + 4 < self.bytecode.len() {
                let selector = &self.bytecode[i..i+4];
                // Common NFT operation patterns
                if selector == [0x40, 0xc1, 0x0f, 0x19] || // mint selector
                   selector == [0x42, 0x96, 0x6c, 0x68] {  // burn selector
                    has_nft_operation = true;
                }
            }
        }
        
        if has_balance_update && !has_nft_operation {
            return Some(Erc404Vulnerability {
                vulnerability_type: Erc404VulnerabilityType::InconsistentState,
                severity: "High".to_string(),
                location: vec![0],
                description: "ERC-404 requires perfect synchronization between ERC20 balances \
                            and NFT ownership. Detected balance updates without corresponding \
                            NFT mint/burn operations.".to_string(),
                exploit_scenario: "1. User has 1000 tokens = 1 NFT\n\
                                  2. Balance modified without NFT adjustment\n\
                                  3. Now shows 2000 tokens but still 1 NFT\n\
                                  4. Can claim 1 additional NFT for free\n\
                                  5. Breaks fundamental ERC-404 invariant".to_string(),
                recommendation: "Always update ERC20 balance and NFT ownership atomically. \
                              Use internal _update function that handles both. Add invariant \
                              checks: assert(balanceOf[user] / UNIT == ownedNFTs[user].length)".to_string(),
            });
        }
        
        None
    }
    
    fn detect_mint_burn_loop_dos(&self) -> Option<Erc404Vulnerability> {
        // ERC-404 may loop through owned NFTs during transfers
        // Expensive if user owns many NFTs
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Pattern: Loop with expensive operations (multiple SSTOREs per iteration)
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 { // JUMP or JUMPI
                let mut sstore_count = 0;
                
                // Count SSTOREs in potential loop body
                for j in i..self.bytecode.len().min(i + 50) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        sstore_count += 1;
                    }
                    
                    // Loop back detected
                    if j > i && (self.bytecode[j] == 0x56 || self.bytecode[j] == 0x57) {
                        if sstore_count >= 3 {
                            return Some(Erc404Vulnerability {
                                vulnerability_type: Erc404VulnerabilityType::MintBurnLoopDos,
                                severity: "High".to_string(),
                                location: vec![i],
                                description: "Transfer operations loop through user's owned NFTs \
                                            performing multiple storage writes per iteration. Gas \
                                            cost grows linearly with NFT count, enabling DOS.".to_string(),
                                exploit_scenario: "1. Attacker accumulates 1000+ NFTs\n\
                                                  2. Each transfer now costs 20M+ gas\n\
                                                  3. Exceeds block gas limit\n\
                                                  4. Funds become locked/untransferrable\n\
                                                  5. Similar to Pandora's initial gas issues".to_string(),
                                recommendation: "Use fixed-cost data structures. DN-404 uses bitmap \
                                              for O(1) operations. Add maxNFTsPerUser limit. Optimize \
                                              _mintNFT to avoid loops. Consider lazy minting.".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        
        None
    }
    
    fn detect_transfer_hook_risks(&self) -> Option<Erc404Vulnerability> {
        // beforeTransfer/afterTransfer hooks can be manipulated
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            // Look for: DELEGATECALL or CALL to external hook
            if self.bytecode[i] == 0xF4 || // DELEGATECALL
               self.bytecode[i] == 0xF1 {  // CALL
                
                return Some(Erc404Vulnerability {
                    vulnerability_type: Erc404VulnerabilityType::TransferHookManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Transfer hooks (beforeTransfer/afterTransfer) allow external \
                                contract calls during token operations. Malicious hooks can \
                                manipulate state or cause reentrancy.".to_string(),
                    exploit_scenario: "1. Attacker deploys malicious hook contract\n\
                                      2. Hook registered for their address\n\
                                      3. During transfer, hook called with full context\n\
                                      4. Hook reenters or manipulates NFT state\n\
                                      5. Bypasses access controls or duplicates assets".to_string(),
                    recommendation: "Disable hooks or make them view-only. If hooks needed, use \
                                  reentrancy guard. Validate hook contracts. Consider DN-404's \
                                  approach: hooks only for approved operators.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_owned_array_bounds(&self) -> Option<Erc404Vulnerability> {
        // ERC-404 tracks owned[] array per user
        // Array access without bounds check = vulnerability
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Pattern: SLOAD from array without length check
            // Look for: MLOAD (array length) ... SLOAD (array access) without LT/GT check between
            
            if self.bytecode[i] == 0x51 { // MLOAD (could be array length)
                let mut found_length_check = false;
                let mut found_array_access = false;
                
                for j in (i+1)..self.bytecode.len().min(i + 15) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x12 { // LT or GT
                        found_length_check = true;
                    }
                    if self.bytecode[j] == 0x54 { // SLOAD (array access)
                        found_array_access = true;
                    }
                }
                
                if found_array_access && !found_length_check {
                    return Some(Erc404Vulnerability {
                        vulnerability_type: Erc404VulnerabilityType::OwnedIndexOutOfBounds,
                        severity: "Critical".to_string(),
                        location: vec![i],
                        description: "Array access in owned[] tracking without proper bounds checking. \
                                    Out-of-bounds access can corrupt storage or cause reverts.".to_string(),
                        exploit_scenario: "1. Manipulate owned[] length via reentrancy\n\
                                          2. Access owned[999] when length = 5\n\
                                          3. Reads/writes wrong storage slot\n\
                                          4. Can corrupt balances, ownership, or admin data\n\
                                          5. Similar to array bugs in early ERC-404 forks".to_string(),
                        recommendation: "Always check: require(index < owned[user].length). Use \
                                      SafeArray library. Add overflow protection on all array \
                                      operations. Consider using mapping instead of array.".to_string(),
                    });
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_erc404_reentrancy_detection() {
        // CALL followed by SSTORE
        let bytecode = vec![
            0xF1, 0x00, 0x00, 0x00, 0x00, // CALL
            0x55, // SSTORE after call
        ];
        
        let detector = Erc404Detector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(matches!(
            vulns[0].vulnerability_type,
            Erc404VulnerabilityType::ReentrancyDuringNftMint
        ));
    }
    
    #[test]
    fn test_erc404_loop_dos_detection() {
        // Loop with multiple SSTOREs
        let bytecode = vec![
            0x56, // JUMP (loop start)
            0x55, 0x55, 0x55, // Multiple SSTOREs
            0x57, // JUMPI (loop back)
        ];
        
        let detector = Erc404Detector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc404VulnerabilityType::MintBurnLoopDos
        )));
    }
}
