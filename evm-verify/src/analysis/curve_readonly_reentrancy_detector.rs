/// Curve Read-Only Reentrancy Detector
/// Detects read-only reentrancy specific to Curve pools
/// where get_virtual_price() can be manipulated during reentrancy

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveReadOnlyVulnerability {
    pub vulnerability_type: CurveIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CurveIssueType {
    VirtualPriceReentrancy,        // get_virtual_price during reentrancy
    UnprotectedPriceRead,          // No reentrancy lock on price reads
    LPTokenPriceManipulation,      // LP token valuation exploit
}

pub struct CurveReadOnlyReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CurveReadOnlyReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CurveReadOnlyVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.interacts_with_curve() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_virtual_price_reentrancy());

        vulnerabilities
    }

    fn interacts_with_curve(&self) -> bool {
        // get_virtual_price(): 0xbb7b8b80
        // add_liquidity(): 0x0b4c7e4d
        let curve_sigs = [
            [0xbb, 0x7b, 0x8b, 0x80],
            [0x0b, 0x4c, 0x7e, 0x4d],
        ];
        
        curve_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == sig)
        })
    }

    fn detect_virtual_price_reentrancy(&self) -> Vec<CurveReadOnlyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(50) {
            // Look for get_virtual_price call
            if self.is_get_virtual_price_call(pc) {
                let has_reentrancy_check = self.has_reentrancy_check_before(pc, 50);
                
                if !has_reentrancy_check {
                    vulnerabilities.push(CurveReadOnlyVulnerability {
                        vulnerability_type: CurveIssueType::VirtualPriceReentrancy,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Calls Curve get_virtual_price() at PC {} without reentrancy protection. \
                            Vulnerable to read-only reentrancy.",
                            pc
                        ),
                        exploit_scenario:
                            "Curve Read-Only Reentrancy (2023 Exploit):\n\
                             1. Call Curve remove_liquidity() which triggers callback\n\
                             2. During callback, call get_virtual_price()\n\
                             3. Curve internal state is inconsistent mid-operation\n\
                             4. get_virtual_price() returns inflated value\n\
                             5. Use inflated price to over-borrow from lending protocol\n\
                             6. Complete Curve operation, price normalizes\n\
                             7. Profit from over-borrowed position\n\n\
                             Fix: Check Curve reentrancy lock before price reads".to_string(),
                        location: pc,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    fn is_get_virtual_price_call(&self, pc: usize) -> bool {
        if pc + 4 >= self.bytecode.len() {
            return false;
        }
        
        self.bytecode[pc..pc+4] == [0xbb, 0x7b, 0x8b, 0x80]
    }

    fn has_reentrancy_check_before(&self, pc: usize, distance: usize) -> bool {
        let start = pc.saturating_sub(distance);
        
        // Look for reentrancy lock check pattern
        for i in start..pc {
            if i + 3 < pc {
                if self.bytecode[i] == 0x54 && // SLOAD
                   self.bytecode[i + 1] == 0x15 && // ISZERO
                   self.bytecode[i + 2] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_price_reentrancy() {
        let bytecode = vec![
            0xbb, 0x7b, 0x8b, 0x80, // get_virtual_price
            // No reentrancy check
        ];
        
        let detector = CurveReadOnlyReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
