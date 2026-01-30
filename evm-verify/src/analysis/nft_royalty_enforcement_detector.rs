/// NFT Royalty Enforcement Vulnerability Detector (ERC2981 + Operator Filter)
///
/// Detects vulnerabilities in NFT royalty enforcement mechanisms including ERC2981
/// (Royalty Standard) and OpenSea's Operator Filter Registry.
///
/// Real-world context:
/// - $100M+ in royalty bypass exploits (Blur vs OpenSea war)
/// - ERC2981 used by 80%+ of new collections
/// - Operator Filter Registry: OpenSea's royalty enforcement
/// - Attack surface: Royalty circumvention, filter bypass, fee manipulation

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftRoyaltyVulnerability {
    pub vulnerability_type: NftRoyaltyVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftRoyaltyVulnerabilityType {
    Erc2981NotImplemented,          // No royalty standard implemented
    RoyaltyReceiverZeroAddress,     // Royalty receiver can be zero
    RoyaltyPercentageExcessive,     // Royalty > 100%
    OperatorFilterBypass,           // OpenSea filter can be bypassed
    RoyaltyReceiverMutable,         // Royalty receiver changeable
    DefaultRoyaltyMissing,          // No default royalty set
    TokenRoyaltyInconsistent,       // Per-token royalties inconsistent
    FilterRegistryNotUsed,          // Not using Operator Filter Registry
    TransferWithoutRoyaltyCheck,    // Transfer doesn't enforce royalties
    RoyaltyFeeSplitVulnerable,      // Fee split logic exploitable
}

pub struct NftRoyaltyEnforcementDetector {
    bytecode: Vec<u8>,
}

impl NftRoyaltyEnforcementDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NftRoyaltyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. ERC2981 not implemented
        if let Some(vuln) = self.detect_erc2981_missing() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Royalty receiver zero address
        if let Some(vuln) = self.detect_zero_royalty_receiver() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Excessive royalty percentage
        if let Some(vuln) = self.detect_excessive_royalty() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Operator filter bypass
        if let Some(vuln) = self.detect_operator_filter_bypass() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Mutable royalty receiver
        if let Some(vuln) = self.detect_mutable_royalty_receiver() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_erc2981_missing(&self) -> Option<NftRoyaltyVulnerability> {
        // Check for ERC2981 royaltyInfo function selector
        let royalty_info_selector = [0x2a, 0x55, 0x20, 0x5a]; // royaltyInfo(uint256,uint256)
        
        let has_royalty_info = self.bytecode.windows(4).any(|w| w == royalty_info_selector);
        
        if !has_royalty_info {
            return Some(NftRoyaltyVulnerability {
                vulnerability_type: NftRoyaltyVulnerabilityType::Erc2981NotImplemented,
                severity: "Medium".to_string(),
                location: vec![0],
                description: "ERC2981 royaltyInfo() function not implemented. Marketplaces cannot \
                            enforce creator royalties, leading to 0% royalties on sales.".to_string(),
                exploit_scenario: "1. NFT collection launches without ERC2981\n\
                                  2. Creator expects 5% royalties on all sales\n\
                                  3. User sells on OpenSea for 10 ETH\n\
                                  4. OpenSea calls royaltyInfo() → function doesn't exist\n\
                                  5. Falls back to 0% royalty\n\
                                  6. Creator gets 0 ETH instead of 0.5 ETH\n\
                                  7. Repeat across all sales\n\
                                  8. Creator loses $1M+ in royalties\n\
                                  9. Collection forced to migrate contracts\n\
                                  10. Similar to early NFT collections pre-ERC2981".to_string(),
                recommendation: "Implement ERC2981: function royaltyInfo(uint256 tokenId, uint256 salePrice) \
                              external view returns (address receiver, uint256 royaltyAmount). \
                              Return (royaltyReceiver, salePrice * royaltyBps / 10000). Add ERC165 support. \
                              Reference: OpenZeppelin ERC2981 implementation.".to_string(),
            });
        }
        
        None
    }
    
    fn detect_zero_royalty_receiver(&self) -> Option<NftRoyaltyVulnerability> {
        // Check for royalty receiver validation
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for royalty receiver storage
            let mut stores_receiver = false;
            let mut validates_nonzero = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Receiver storage (SSTORE)
                if self.bytecode[j] == 0x55 {
                    stores_receiver = true;
                }
                
                // Zero address check
                if self.bytecode[j] == 0x15 { // ISZERO
                    if j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0xFD { // REVERT
                        validates_nonzero = true;
                    }
                }
            }
            
            if stores_receiver && !validates_nonzero {
                return Some(NftRoyaltyVulnerability {
                    vulnerability_type: NftRoyaltyVulnerabilityType::RoyaltyReceiverZeroAddress,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Royalty receiver can be set to zero address. All royalty payments \
                                lost permanently, burning creator revenue.".to_string(),
                    exploit_scenario: "1. Contract allows setting royalty receiver\n\
                                      2. No validation that receiver != address(0)\n\
                                      3. Admin accidentally sets receiver = address(0)\n\
                                      4. Or malicious admin intentionally sets to zero\n\
                                      5. Sales continue normally\n\
                                      6. Marketplaces send royalties to address(0)\n\
                                      7. All royalty payments burned\n\
                                      8. $500K ETH lost to void\n\
                                      9. No way to recover burned funds".to_string(),
                    recommendation: "Validate receiver: require(receiver != address(0)). Add receiver \
                                  change validation. Use two-step receiver update. Implement emergency \
                                  recovery. Add receiver whitelist. Reference: Safe receiver pattern.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_excessive_royalty(&self) -> Option<NftRoyaltyVulnerability> {
        // Check for royalty percentage bounds
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for royalty calculation
            let mut calculates_royalty = false;
            let mut checks_maximum = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                // Royalty calculation (MUL/DIV)
                if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 { // MUL/DIV
                    calculates_royalty = true;
                }
                
                // Maximum check
                if self.bytecode[j] == 0x10 { // LT (checking < max)
                    checks_maximum = true;
                }
            }
            
            if calculates_royalty && !checks_maximum {
                return Some(NftRoyaltyVulnerability {
                    vulnerability_type: NftRoyaltyVulnerabilityType::RoyaltyPercentageExcessive,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Royalty percentage unbounded. Can be set >100%, causing marketplace \
                                transactions to fail or funds to be locked.".to_string(),
                    exploit_scenario: "1. Royalty percentage stored in basis points\n\
                                      2. No validation that royaltyBps <= 10000 (100%)\n\
                                      3. Admin sets royaltyBps = 50000 (500%)\n\
                                      4. User tries to sell NFT for 1 ETH\n\
                                      5. Marketplace calculates: 1 ETH * 500% = 5 ETH royalty\n\
                                      6. Requires buyer to pay 6 ETH total\n\
                                      7. Transaction reverts or marketplace blocks listing\n\
                                      8. NFT becomes unsellable\n\
                                      9. Collection value drops to zero\n\
                                      10. $10M market cap destroyed".to_string(),
                    recommendation: "Cap royalty: require(royaltyBps <= 10000). Typical max is 10% (1000 bps). \
                                  Add royalty bounds check on update. Validate in royaltyInfo(). \
                                  Use safe percentage calculations. Reference: ERC2981 best practices.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_operator_filter_bypass(&self) -> Option<NftRoyaltyVulnerability> {
        // Check for Operator Filter Registry usage
        let operator_filter_registry = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x26]; // Partial address
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for transfer function
            let mut has_transfer = false;
            let mut checks_operator_filter = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Transfer logic
                if self.bytecode[j] == 0x55 { // SSTORE (ownership change)
                    has_transfer = true;
                }
                
                // Operator filter check (CALL to registry)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA { // CALL/STATICCALL
                    checks_operator_filter = true;
                }
            }
            
            if has_transfer && !checks_operator_filter {
                return Some(NftRoyaltyVulnerability {
                    vulnerability_type: NftRoyaltyVulnerabilityType::OperatorFilterBypass,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Transfer doesn't use Operator Filter Registry. Traders can bypass \
                                royalty enforcement by using non-compliant marketplaces.".to_string(),
                    exploit_scenario: "1. Collection wants to enforce royalties via OpenSea filter\n\
                                      2. transfer() and transferFrom() don't check filter registry\n\
                                      3. User lists NFT on Blur (no royalties)\n\
                                      4. Buyer purchases on Blur\n\
                                      5. Blur calls transferFrom() directly\n\
                                      6. No filter check → transfer succeeds\n\
                                      7. 0% royalty paid to creator\n\
                                      8. Creator expected 5% ($500 on $10K sale)\n\
                                      9. Repeat across all sales\n\
                                      10. Creator loses $1M+ to filter bypass".to_string(),
                    recommendation: "Use Operator Filter Registry: IERC721(registry).isOperatorAllowed(). \
                                  Add onlyAllowedOperator modifier. Check before transfers. Implement \
                                  filter subscription. Reference: OpenSea DefaultOperatorFilterer.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_mutable_royalty_receiver(&self) -> Option<NftRoyaltyVulnerability> {
        // Check if royalty receiver can be changed without protection
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for receiver update function
            let mut updates_receiver = false;
            let mut has_access_control = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Receiver update (SSTORE)
                if self.bytecode[j] == 0x55 {
                    updates_receiver = true;
                }
                
                // Access control (onlyOwner, etc.)
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        has_access_control = true;
                    }
                }
            }
            
            if updates_receiver && !has_access_control {
                return Some(NftRoyaltyVulnerability {
                    vulnerability_type: NftRoyaltyVulnerabilityType::RoyaltyReceiverMutable,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Royalty receiver can be changed without access control. Attacker \
                                can redirect all future royalties to themselves.".to_string(),
                    exploit_scenario: "1. Collection earns 5% royalties on all sales\n\
                                      2. setRoyaltyReceiver() has no onlyOwner modifier\n\
                                      3. Attacker calls setRoyaltyReceiver(attackerAddress)\n\
                                      4. All future royalty payments go to attacker\n\
                                      5. $100K sale → $5K royalty to attacker\n\
                                      6. Creator gets nothing\n\
                                      7. Attacker drains all ongoing royalties\n\
                                      8. $1M+ stolen over collection lifetime\n\
                                      9. Similar to ownership takeover".to_string(),
                    recommendation: "Add access control: require(msg.sender == owner). Use onlyOwner \
                                  modifier. Implement multi-sig for receiver changes. Add timelock. \
                                  Emit events on receiver change. Consider immutable receiver. \
                                  Reference: OpenZeppelin Ownable pattern.".to_string(),
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
    fn test_erc2981_missing() {
        // No royaltyInfo selector
        let bytecode = vec![
            0x00, 0x01, 0x02, // Random bytecode without royaltyInfo
        ];
        
        let detector = NftRoyaltyEnforcementDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            NftRoyaltyVulnerabilityType::Erc2981NotImplemented
        )));
    }
    
    #[test]
    fn test_zero_royalty_receiver() {
        // Receiver storage without zero check
        let bytecode = vec![
            0x55, // SSTORE (no ISZERO check)
        ];
        
        let detector = NftRoyaltyEnforcementDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            NftRoyaltyVulnerabilityType::RoyaltyReceiverZeroAddress
        )));
    }
    
    #[test]
    fn test_excessive_royalty() {
        // Royalty calculation without max check
        let bytecode = vec![
            0x02, // MUL (no LT check)
        ];
        
        let detector = NftRoyaltyEnforcementDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            NftRoyaltyVulnerabilityType::RoyaltyPercentageExcessive
        )));
    }
    
    #[test]
    fn test_mutable_royalty_receiver() {
        // Receiver update without access control
        let bytecode = vec![
            0x55, // SSTORE (no CALLER check)
        ];
        
        let detector = NftRoyaltyEnforcementDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            NftRoyaltyVulnerabilityType::RoyaltyReceiverMutable
        )));
    }
}
