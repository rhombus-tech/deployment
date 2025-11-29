/// Collateral Ratio Manipulation Detector (CDP-style protocols)
/// Detects manipulation of collateral ratios during liquidation checks
/// (MakerDAO, Aave, Compound style lending protocols)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralRatioVulnerability {
    pub vulnerability_type: CollateralIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollateralIssueType {
    FlashLoanPriceManipulation,    // Manipulate price during liquidation check
    StaleCollateralPrice,          // Using old price for collateral value
    CircularPriceReference,        // Collateral price depends on borrowed asset
    AtomicLiquidationExploit,      // Liquidate + price manipulation in same tx
}

pub struct CollateralRatioDetector {
    bytecode: Vec<u8>,
}

impl CollateralRatioDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CollateralRatioVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_lending_protocol() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_atomic_liquidation_risk());
        vulnerabilities.extend(self.detect_stale_price_usage());

        vulnerabilities
    }

    fn is_lending_protocol(&self) -> bool {
        let lending_sigs = [
            [0xc5, 0xea, 0xbe, 0xdf], // borrow()
            [0x69, 0x32, 0x8d, 0xec], // liquidate()
            [0xdb, 0x00, 0x6a, 0x75], // deposit() / supply()
        ];
        
        lending_sigs.iter()
            .filter(|sig| self.bytecode.windows(4).any(|w| w == *sig))
            .count() >= 2
    }

    fn detect_atomic_liquidation_risk(&self) -> Vec<CollateralRatioVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(liquidate_pc) = self.find_liquidate_function() {
            let has_reentrancy_guard = self.has_reentrancy_protection(liquidate_pc, 50);
            let reads_oracle = self.reads_oracle_in_function(liquidate_pc, 200);
            
            if reads_oracle && !has_reentrancy_guard {
                vulnerabilities.push(CollateralRatioVulnerability {
                    vulnerability_type: CollateralIssueType::AtomicLiquidationExploit,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.80,
                    description:
                        "Liquidation function reads oracle price without reentrancy protection. \
                        Vulnerable to flash loan + liquidation attack.".to_string(),
                    exploit_scenario:
                        "Atomic Liquidation Attack:\n\
                         1. Flash borrow 10M USDC from Aave\n\
                         2. Swap USDC → ETH, crashing ETH price on AMM\n\
                         3. Call liquidate() on CDP protocol\n\
                         4. Oracle reads manipulated ETH price\n\
                         5. Healthy positions become underwater\n\
                         6. Liquidate at discount, profit from liquidation bonus\n\
                         7. Reverse swap, repay flash loan\n\n\
                         Fix: TWAP oracle + reentrancy guard".to_string(),
                    location: liquidate_pc,
                });
            }
        }

        vulnerabilities
    }

    fn detect_stale_price_usage(&self) -> Vec<CollateralRatioVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(50) {
            if self.looks_like_collateral_check(pc) {
                let has_fresh_oracle = self.has_fresh_oracle_read(pc, 30);
                
                if !has_fresh_oracle {
                    vulnerabilities.push(CollateralRatioVulnerability {
                        vulnerability_type: CollateralIssueType::StaleCollateralPrice,
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Collateral ratio check at PC {} may use stale price. \
                            No fresh oracle read detected.",
                            pc
                        ),
                        exploit_scenario:
                            "Stale Price Exploit:\n\
                             1. Collateral price cached from previous block\n\
                             2. Market moves 10% against position\n\
                             3. Cached price still shows healthy position\n\
                             4. Position should be liquidatable but isn't\n\
                             5. Protocol accrues bad debt\n\n\
                             Fix: Always read fresh oracle price for liquidations".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn find_liquidate_function(&self) -> Option<usize> {
        let selector = [0x69, 0x32, 0x8d, 0xec]; // liquidate()
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn has_reentrancy_protection(&self, start: usize, distance: usize) -> bool {
        let begin = start.saturating_sub(distance);
        
        // Look for status check pattern (ReentrancyGuard)
        for i in begin..start {
            if i + 3 < start {
                if self.bytecode[i] == 0x54 && // SLOAD
                   self.bytecode[i + 1] == 0x14 && // EQ
                   self.bytecode[i + 2] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        false
    }

    fn reads_oracle_in_function(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // Chainlink latestRoundData: 0xfeaf968c
        let oracle_sig = [0xfe, 0xaf, 0x96, 0x8c];
        
        self.bytecode[start..end].windows(4).any(|w| w == oracle_sig)
    }

    fn looks_like_collateral_check(&self, pc: usize) -> bool {
        // Collateral check pattern: Load two values, multiply/divide, compare
        if pc + 10 >= self.bytecode.len() {
            return false;
        }
        
        let has_loads = self.bytecode[pc..pc+10].iter()
            .filter(|&&op| op == 0x54)
            .count() >= 2; // At least 2 SLOADs
        
        let has_math = self.bytecode[pc..pc+10].iter()
            .any(|&op| matches!(op, 0x02 | 0x04)); // MUL or DIV
        
        let has_comparison = self.bytecode[pc..pc+10].iter()
            .any(|&op| matches!(op, 0x10 | 0x11)); // LT or GT
        
        has_loads && has_math && has_comparison
    }

    fn has_fresh_oracle_read(&self, start: usize, distance: usize) -> bool {
        let begin = start.saturating_sub(distance);
        let end = (start + distance).min(self.bytecode.len());
        
        // Look for oracle call nearby
        let oracle_sigs = [
            [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData
            [0x50, 0xd2, 0x5b, 0xcd], // latestAnswer
        ];
        
        oracle_sigs.iter().any(|sig| {
            self.bytecode[begin..end].windows(4).any(|w| w == sig)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_liquidation_risk() {
        let bytecode = vec![
            0x69, 0x32, 0x8d, 0xec, // liquidate() selector
            0xfe, 0xaf, 0x96, 0x8c, // latestRoundData (oracle)
            // No reentrancy guard pattern
        ];
        
        let detector = CollateralRatioDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
