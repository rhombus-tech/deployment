/// Balancer Weighted Pool Manipulation Detector
/// Detects weight manipulation vulnerabilities in Balancer-style pools

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerWeightVulnerability {
    pub vulnerability_type: BalancerIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerIssueType {
    WeightManipulationDuringSwap,  // Manipulate weights during swap
    GradualWeightUpdateExploit,    // Exploit weight update periods
    UnprotectedWeightChange,       // No access control on weights
}

pub struct BalancerWeightDetector {
    bytecode: Vec<u8>,
}

impl BalancerWeightDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalancerWeightVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_balancer_pool() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_weight_manipulation());

        vulnerabilities
    }

    fn is_balancer_pool(&self) -> bool {
        // getNormalizedWeights(): 0xf89f27ed
        // updateWeightsGradually(): 0x7c5e9ea4
        let balancer_sigs = [
            [0xf8, 0x9f, 0x27, 0xed],
            [0x7c, 0x5e, 0x9e, 0xa4],
        ];
        
        balancer_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == sig)
        })
    }

    fn detect_weight_manipulation(&self) -> Vec<BalancerWeightVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(swap_pc) = self.find_swap_function() {
            let reads_weights = self.reads_weights_in_function(swap_pc, 200);
            let has_weight_lock = self.has_weight_update_lock(swap_pc, 50);
            
            if reads_weights && !has_weight_lock {
                vulnerabilities.push(BalancerWeightVulnerability {
                    vulnerability_type: BalancerIssueType::WeightManipulationDuringSwap,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description:
                        "Swap function reads weights without checking for ongoing updates. \
                        Can be exploited during gradual weight changes.".to_string(),
                    exploit_scenario:
                        "Weight Manipulation Attack:\n\
                         1. Admin starts gradual weight update (50/50 → 80/20)\n\
                         2. During update period, weights are changing\n\
                         3. Attacker swaps when weights temporarily favor one side\n\
                         4. Gets better price than intended\n\
                         5. Arbitrage profit from weight imbalance\n\n\
                         Fix: Lock swaps during weight updates or use TWAP weights".to_string(),
                    location: swap_pc,
                });
            }
        }

        vulnerabilities
    }

    fn find_swap_function(&self) -> Option<usize> {
        // swap(): 0x022c0d9f (Balancer style)
        let selector = [0x02, 0x2c, 0x0d, 0x9f];
        self.bytecode.windows(4).position(|w| w == selector)
    }

    fn reads_weights_in_function(&self, start: usize, distance: usize) -> bool {
        let end = (start + distance).min(self.bytecode.len());
        
        // getNormalizedWeights selector
        let weight_sig = [0xf8, 0x9f, 0x27, 0xed];
        
        self.bytecode[start..end].windows(4).any(|w| w == weight_sig)
    }

    fn has_weight_update_lock(&self, start: usize, distance: usize) -> bool {
        let begin = start.saturating_sub(distance);
        
        // Look for check that weight update is not in progress
        for i in begin..start {
            if i + 3 < start {
                if self.bytecode[i] == 0x54 && // SLOAD (check update status)
                   self.bytecode[i + 1] == 0x15 && // ISZERO (require not updating)
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
    fn test_weight_manipulation() {
        let bytecode = vec![
            0x02, 0x2c, 0x0d, 0x9f, // swap() selector
            0xf8, 0x9f, 0x27, 0xed, // getNormalizedWeights
            // No weight update lock
        ];
        
        let detector = BalancerWeightDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
