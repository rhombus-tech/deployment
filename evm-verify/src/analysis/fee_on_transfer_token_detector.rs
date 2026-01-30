/// Fee-on-Transfer Token Incompatibility Detector
///
/// Some tokens (USDT, STA, PAXG) take a fee on transfer, causing:
/// - Actual received amount < transferred amount
/// - Balance accounting errors
/// - Vault share calculation bugs
///
/// Famous exploits: Multiple DeFi protocols with deflationary tokens

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeOnTransferVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub vulnerable_pattern: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct FeeOnTransferTokenDetector {
    bytecode: Vec<u8>,
}

impl FeeOnTransferTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<FeeOnTransferVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_unverified_transfer_amount());
        vulnerabilities.extend(self.detect_share_calculation_without_balance_check());
        vulnerabilities.extend(self.detect_mint_based_on_amount_not_received());
        
        vulnerabilities
    }
    
    fn detect_unverified_transfer_amount(&self) -> Vec<FeeOnTransferVulnerability> {
        let mut vulns = Vec::new();
        
        // Pattern: transferFrom without checking actual received amount
        // Safe pattern: balanceBefore = balanceOf(this); transferFrom(); balanceAfter = balanceOf(this); actualAmount = after - before;
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for transferFrom call
            if self.is_transfer_from_call(i) {
                let transfer_pc = i;
                
                // Check if contract reads balance before transfer
                let has_balance_before = self.has_balance_check_before(transfer_pc);
                // Check if contract reads balance after transfer
                let has_balance_after = self.has_balance_check_after(transfer_pc);
                
                if !has_balance_before || !has_balance_after {
                    vulns.push(FeeOnTransferVulnerability {
                        vulnerability_type: "Unverified Transfer Amount".to_string(),
                        severity: "High".to_string(),
                        location: transfer_pc,
                        description: "Transfer amount not verified against actual received amount".to_string(),
                        vulnerable_pattern: "transferFrom(user, amount) without checking balanceOf() delta".to_string(),
                        exploit_scenario: 
                            "With fee-on-transfer token:\n\
                             1. User deposits 100 tokens\n\
                             2. Contract receives only 99 (1% fee)\n\
                             3. Contract credits user for 100 tokens\n\
                             4. Protocol insolvent by fee amount".to_string(),
                        remediation: 
                            "uint256 balanceBefore = token.balanceOf(this);\n\
                             token.transferFrom(from, this, amount);\n\
                             uint256 actualAmount = token.balanceOf(this) - balanceBefore;".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn detect_share_calculation_without_balance_check(&self) -> Vec<FeeOnTransferVulnerability> {
        let mut vulns = Vec::new();
        
        // Pattern: Vault share calculation based on amount parameter, not actual received
        // shares = (amount * totalShares) / totalAssets
        // But if fee-on-transfer, actual received < amount!
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_transfer_from_call(i) {
                // Look for multiplication/division after transfer (share calculation)
                let end = (i + 80).min(self.bytecode.len());
                let has_share_calc = if end > i {
                    self.bytecode[i..end]
                        .windows(2)
                        .any(|w| {
                            (w[0] == 0x02 && w[1] == 0x04) || // MUL then DIV
                            (w[0] == 0x04 && w[1] == 0x02)    // DIV then MUL
                        })
                } else {
                    false
                };
                
                if has_share_calc {
                    // Check if calculation uses balanceOf() delta or just the amount parameter
                    let uses_balance_delta = self.has_balance_delta_calculation(i);
                    
                    if !uses_balance_delta {
                        vulns.push(FeeOnTransferVulnerability {
                            vulnerability_type: "Share Calculation with Fee-on-Transfer Bug".to_string(),
                            severity: "Critical".to_string(),
                            location: i,
                            description: "Vault shares calculated from transfer amount, not actual received".to_string(),
                            vulnerable_pattern: "shares = amount * totalShares / totalAssets (using amount parameter)".to_string(),
                            exploit_scenario:
                                "ERC4626 vault with fee-on-transfer token:\n\
                                 1. Deposit 100 tokens (98 actually received after 2% fee)\n\
                                 2. Shares minted for 100 tokens worth\n\
                                 3. User can immediately withdraw 100 tokens\n\
                                 4. Vault drained by 2% per deposit".to_string(),
                            remediation: "Use actual received amount: actualAmount = balanceAfter - balanceBefore".to_string(),
                        });
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_mint_based_on_amount_not_received(&self) -> Vec<FeeOnTransferVulnerability> {
        let mut vulns = Vec::new();
        
        // Pattern: Minting tokens based on transfer amount without verification
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_transfer_from_call(i) {
                // Look for SSTORE after transfer (could be minting/crediting)
                for j in i+1..i+50.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE (balance update/mint)
                        // Check if amount used is from parameter or from balance delta
                        let uses_param = true; // Simplified - would check stack analysis
                        let verifies_received = self.has_balance_check_after(i);
                        
                        if uses_param && !verifies_received {
                            vulns.push(FeeOnTransferVulnerability {
                                vulnerability_type: "Mint Amount Mismatch".to_string(),
                                severity: "High".to_string(),
                                location: i,
                                description: "Minting/crediting based on transfer parameter, not actual received".to_string(),
                                vulnerable_pattern: "balances[user] += amount (without verifying actual transfer)".to_string(),
                                exploit_scenario: "User transfers 100 tokens with 10% fee, receives credit for 100".to_string(),
                                remediation: "Credit based on actual received: balances[user] += actualReceived".to_string(),
                            });
                        }
                        break;
                    }
                }
            }
        }
        
        vulns
    }
    
    fn is_transfer_from_call(&self, pc: usize) -> bool {
        // Check for transferFrom selector nearby: 0x23b872dd
        let transfer_from = [0x23, 0xb8, 0x72, 0xdd];
        
        if pc < 10 {
            return false;
        }
        
        let end = (pc + 10).min(self.bytecode.len());
        if end <= pc { return false; }
        self.bytecode[pc.saturating_sub(10)..end]
            .windows(4)
            .any(|w| w == transfer_from)
    }
    
    fn has_balance_check_before(&self, transfer_pc: usize) -> bool {
        // Look for balanceOf call before transfer
        // balanceOf selector: 0x70a08231
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        
        self.bytecode[transfer_pc.saturating_sub(30)..transfer_pc]
            .windows(4)
            .any(|w| w == balance_of)
    }
    
    fn has_balance_check_after(&self, transfer_pc: usize) -> bool {
        // Look for balanceOf call after transfer
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        
        self.bytecode[transfer_pc..transfer_pc+50.min(self.bytecode.len())]
            .windows(4)
            .any(|w| w == balance_of)
    }
    
    fn has_balance_delta_calculation(&self, transfer_pc: usize) -> bool {
        // Check if code calculates: balanceAfter - balanceBefore
        // Pattern: Two balanceOf calls with SUB operation between them
        
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        let window = &self.bytecode[transfer_pc.saturating_sub(40)..transfer_pc+60.min(self.bytecode.len())];
        
        let balance_count = window.windows(4).filter(|w| *w == balance_of).count();
        let has_sub = window.iter().any(|&op| op == 0x03); // SUB
        
        balance_count >= 2 && has_sub
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_unverified_transfer() {
        let bytecode = vec![
            0x23, 0xb8, 0x72, 0xdd, // transferFrom selector
            0x55,                    // SSTORE (credit user)
        ];
        
        let detector = FeeOnTransferTokenDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_safe_verified_transfer() {
        let bytecode = vec![
            0x70, 0xa0, 0x82, 0x31, // balanceOf (before)
            0x23, 0xb8, 0x72, 0xdd, // transferFrom
            0x70, 0xa0, 0x82, 0x31, // balanceOf (after)
            0x03,                    // SUB (calculate delta)
            0x55,                    // SSTORE (credit actual amount)
        ];
        
        let detector = FeeOnTransferTokenDetector::new(bytecode);
        let vulns = detector.detect_unverified_transfer_amount();
        
        assert_eq!(vulns.len(), 0); // Should be safe
    }
}
