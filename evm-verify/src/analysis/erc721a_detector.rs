/// ERC721A Gas-Optimized NFT Vulnerability Detector
///
/// Detects vulnerabilities specific to ERC721A, the gas-optimized NFT standard
/// popularized by Azuki. ERC721A optimizes batch minting but introduces unique bugs.
///
/// Real-world context:
/// - Used by 50%+ of new NFT collections (Azuki, Beanz, etc.)
/// - $300M+ in Azuki alone
/// - Attack surface: Ownership index bugs, quantity overflow, transferFrom edge cases
/// - Risk: Multiple collections exploited due to misunderstanding ERC721A mechanics

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc721aVulnerability {
    pub vulnerability_type: Erc721aVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc721aVulnerabilityType {
    OwnershipIndexCorruption,       // _ownerships array corrupted
    QuantityOverflow,               // Quantity field overflows
    StartTokenIdMismatch,           // _startTokenId() inconsistent
    AuxDataCollision,               // Auxiliary data overwrites ownership
    TransferFromUninitialized,      // Transfer of uninitialized token
    BatchMintDoS,                   // Batch mint causes out-of-gas
    CurrentIndexManipulation,       // _currentIndex manipulated
    BurnedTokenTransfer,            // Burned token can be transferred
    ExplicitOwnershipMissing,       // explicitOwnershipOf() not used
    TokenDataPacking,               // Packed token data corrupted
}

pub struct Erc721aDetector {
    bytecode: Vec<u8>,
}

impl Erc721aDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc721aVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Ownership index corruption
        if let Some(vuln) = self.detect_ownership_index_corruption() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Quantity overflow
        if let Some(vuln) = self.detect_quantity_overflow() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Transfer from uninitialized
        if let Some(vuln) = self.detect_transfer_uninitialized() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Batch mint DoS
        if let Some(vuln) = self.detect_batch_mint_dos() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Burned token transfer
        if let Some(vuln) = self.detect_burned_token_transfer() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_ownership_index_corruption(&self) -> Option<Erc721aVulnerability> {
        // ERC721A uses _ownerships mapping - must be updated correctly
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for ownership update without bounds check
            let mut updates_ownership = false;
            let mut checks_bounds = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Ownership update (SSTORE to ownership slot)
                if self.bytecode[j] == 0x55 { // SSTORE
                    updates_ownership = true;
                }
                
                // Bounds check (tokenId < totalSupply)
                if self.bytecode[j] == 0x10 { // LT
                    checks_bounds = true;
                }
            }
            
            if updates_ownership && !checks_bounds {
                return Some(Erc721aVulnerability {
                    vulnerability_type: Erc721aVulnerabilityType::OwnershipIndexCorruption,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "ERC721A ownership array updated without bounds checking. Out-of-bounds \
                                write can corrupt contract storage and steal NFTs.".to_string(),
                    exploit_scenario: "1. Collection uses ERC721A for gas-efficient minting\n\
                                      2. _ownerships array stores packed ownership data\n\
                                      3. Transfer function doesn't validate tokenId bounds\n\
                                      4. Attacker calls transferFrom with tokenId = 2^256-1\n\
                                      5. Out-of-bounds write corrupts ownership of token 0\n\
                                      6. Attacker now owns token 0 (e.g., rare Azuki #0)\n\
                                      7. Steals token worth $500K+\n\
                                      8. Similar to CryptoPunks v1 overflow bug\n\
                                      9. $10M+ at risk in major collections".to_string(),
                    recommendation: "Validate tokenId bounds: require(tokenId < _currentIndex). \
                                  Use _exists(tokenId) check. Validate ownership before transfer. \
                                  Add bounds checking to all array accesses. Use SafeMath for indices. \
                                  Reference: ERC721A ownerOf() implementation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_quantity_overflow(&self) -> Option<Erc721aVulnerability> {
        // ERC721A stores quantity in packed struct - can overflow
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for quantity manipulation
            let mut modifies_quantity = false;
            let mut checks_overflow = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Quantity modification (ADD to packed data)
                if self.bytecode[j] == 0x01 { // ADD
                    modifies_quantity = true;
                }
                
                // Overflow check
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                    checks_overflow = true;
                }
            }
            
            if modifies_quantity && !checks_overflow {
                return Some(Erc721aVulnerability {
                    vulnerability_type: Erc721aVulnerabilityType::QuantityOverflow,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "ERC721A quantity field can overflow. Attacker can mint more NFTs \
                                than max supply or corrupt ownership data.".to_string(),
                    exploit_scenario: "1. ERC721A packs ownership: (addr, startTimestamp, burned, quantity)\n\
                                      2. Quantity is uint64 (max 2^64-1)\n\
                                      3. Batch mint doesn't check quantity overflow\n\
                                      4. Attacker mints quantity = 2^64-1\n\
                                      5. Next mint causes overflow: 2^64-1 + 1 = 0\n\
                                      6. Ownership data corrupted\n\
                                      7. Attacker can claim any token\n\
                                      8. Or mint exceeds max supply\n\
                                      9. $5M+ collection supply broken".to_string(),
                    recommendation: "Check quantity overflow: require(quantity <= type(uint64).max). \
                                  Validate totalSupply after mint. Use unchecked blocks carefully. \
                                  Add maximum quantity per mint. Verify packed data integrity. \
                                  Reference: ERC721A _safeMint() quantity checks.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_transfer_uninitialized(&self) -> Option<Erc721aVulnerability> {
        // ERC721A allows transfers before explicit initialization
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for transfer logic
            let mut performs_transfer = false;
            let mut checks_initialized = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Transfer (ownership change via SSTORE)
                if self.bytecode[j] == 0x55 { // SSTORE
                    performs_transfer = true;
                }
                
                // Initialization check (addr != 0)
                if self.bytecode[j] == 0x15 { // ISZERO (checking if initialized)
                    checks_initialized = true;
                }
            }
            
            if performs_transfer && !checks_initialized {
                return Some(Erc721aVulnerability {
                    vulnerability_type: Erc721aVulnerabilityType::TransferFromUninitialized,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "ERC721A transfer doesn't check if token ownership is initialized. \
                                Uninitialized tokens can be transferred, stealing from real owners.".to_string(),
                    exploit_scenario: "1. User batch mints tokens 100-109 (10 tokens)\n\
                                      2. ERC721A only stores ownership for token 100\n\
                                      3. Tokens 101-109 have uninitialized ownership\n\
                                      4. ownerOf(105) walks back to find token 100's owner\n\
                                      5. Attacker calls transferFrom for token 105\n\
                                      6. No initialization check\n\
                                      7. Sets ownership[105] = attacker\n\
                                      8. Real owner loses token 105\n\
                                      9. $50K NFT stolen\n\
                                      10. Multiply across collection for $1M+ exploit".to_string(),
                    recommendation: "Check initialization: require(_ownerships[tokenId].addr != address(0) || \
                                  _ownershipOf(tokenId).addr != address(0)). Use _exists() check. \
                                  Explicitly initialize on first transfer. Add ownership validation. \
                                  Reference: ERC721A transferFrom() implementation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_batch_mint_dos(&self) -> Option<Erc721aVulnerability> {
        // ERC721A batch mint must have reasonable limits
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for batch mint loop
            let mut has_mint_loop = false;
            let mut has_gas_limit = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Loop (JUMPI pattern)
                if self.bytecode[j] == 0x57 { // JUMPI
                    has_mint_loop = true;
                }
                
                // Gas or quantity limit check
                if self.bytecode[j] == 0x10 { // LT (checking limit)
                    if j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0xFD { // REVERT
                        has_gas_limit = true;
                    }
                }
            }
            
            if has_mint_loop && !has_gas_limit {
                return Some(Erc721aVulnerability {
                    vulnerability_type: Erc721aVulnerabilityType::BatchMintDoS,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "ERC721A batch mint lacks quantity limit. Attacker can cause out-of-gas \
                                for all future mints, permanently DoSing the collection.".to_string(),
                    exploit_scenario: "1. ERC721A allows batch minting for gas efficiency\n\
                                      2. No maximum quantity per mint\n\
                                      3. Attacker calls mint(quantity = 10000)\n\
                                      4. Runs out of gas mid-mint\n\
                                      5. _currentIndex partially updated\n\
                                      6. Collection in broken state\n\
                                      7. All future mints fail\n\
                                      8. Collection permanently bricked\n\
                                      9. $10M collection destroyed\n\
                                      10. Similar to Akutar $34M lockup".to_string(),
                    recommendation: "Add quantity limit: require(quantity <= MAX_BATCH_SIZE). \
                                  Typical limit is 5-20 per tx. Check gas remaining. Use try-catch \
                                  for batch operations. Add emergency pause. Reference: Azuki \
                                  maxBatchSize pattern.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_burned_token_transfer(&self) -> Option<Erc721aVulnerability> {
        // ERC721A burned tokens must be untransferable
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for transfer with burn check
            let mut transfers_token = false;
            let mut checks_burned = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Token transfer
                if self.bytecode[j] == 0x55 { // SSTORE
                    transfers_token = true;
                }
                
                // Burned flag check
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x16 { // AND (checking flag)
                        checks_burned = true;
                    }
                }
            }
            
            if transfers_token && !checks_burned {
                return Some(Erc721aVulnerability {
                    vulnerability_type: Erc721aVulnerabilityType::BurnedTokenTransfer,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Transfer doesn't check if token is burned. Burned tokens can be \
                                transferred, breaking burn mechanism and supply tracking.".to_string(),
                    exploit_scenario: "1. User burns token 500 to reduce supply\n\
                                      2. Token marked as burned in packed data\n\
                                      3. transferFrom doesn't check burned flag\n\
                                      4. Attacker calls transferFrom on burned token\n\
                                      5. Transfer succeeds\n\
                                      6. Token 500 now owned by attacker\n\
                                      7. Supply count wrong (shows as burned but exists)\n\
                                      8. Rarity calculations broken\n\
                                      9. Marketplace confused about supply".to_string(),
                    recommendation: "Check burned flag: require(!_ownerships[tokenId].burned). \
                                  Validate token existence before transfer. Use _exists() helper. \
                                  Add burned token registry. Revert on burned token operations. \
                                  Reference: ERC721A burn() implementation.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ownership_index_corruption() {
        // Ownership update without bounds check
        let bytecode = vec![
            0x55, // SSTORE (no LT check)
        ];
        
        let detector = Erc721aDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc721aVulnerabilityType::OwnershipIndexCorruption
        )));
    }
    
    #[test]
    fn test_quantity_overflow() {
        // Quantity modification without overflow check
        let bytecode = vec![
            0x01, // ADD (no overflow check)
        ];
        
        let detector = Erc721aDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc721aVulnerabilityType::QuantityOverflow
        )));
    }
    
    #[test]
    fn test_batch_mint_dos() {
        // Mint loop without gas limit
        let bytecode = vec![
            0x57, // JUMPI (loop without limit check)
        ];
        
        let detector = Erc721aDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc721aVulnerabilityType::BatchMintDoS
        )));
    }
}
