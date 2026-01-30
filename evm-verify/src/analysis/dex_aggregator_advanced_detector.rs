/// DEX Aggregator Advanced Detector (Paraswap, KyberSwap)
/// Multi-hop routing and aggregation

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexAggregatorAdvancedVulnerability {
    pub vulnerability_type: DexAggregatorVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DexAggregatorVulnerabilityType {
    RoutingManipulation,            // Manipulate routing path
    FeeExtractionExploit,           // Hidden fee extraction
    PartialFillExploit,             // Partial fill manipulation
    SlippageBypass,                 // Bypass slippage protection
    ApprovalFrontrunning,           // Frontrun token approvals
}

pub struct DexAggregatorAdvancedDetector {
    bytecode: Vec<u8>,
}

impl DexAggregatorAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<DexAggregatorAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Multi-hop without output validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut multi_hop_swap = false;
            let mut validates_output = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0xF1 && j + 5 < self.bytecode.len() && self.bytecode[j+5] == 0xF1 { // Multiple CALLs
                    multi_hop_swap = true;
                }
                if self.bytecode[j] == 0x10 { validates_output = true; } // LT (min output)
            }
            
            if multi_hop_swap && !validates_output {
                vulnerabilities.push(DexAggregatorAdvancedVulnerability {
                    vulnerability_type: DexAggregatorVulnerabilityType::RoutingManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Multi-hop swap without final output validation.".to_string(),
                    exploit_scenario: "1. User wants to swap 10 ETH → USDC via aggregator\n\
                                      2. Aggregator routes: ETH → WBTC → USDC (3 hops)\n\
                                      3. User sets minAmountOut = 19,000 USDC\n\
                                      4. Each hop validated individually\n\
                                      5. Malicious router in middle hop\n\
                                      6. Takes 10% fee per hop\n\
                                      7. Final output: 14,580 USDC\n\
                                      8. Below minAmountOut but passes per-hop checks\n\
                                      9. User loses $4,420 to hidden routing fees".to_string(),
                    recommendation: "Validate final output amount. Check total slippage across all hops. \
                                  Use trusted router registry.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
