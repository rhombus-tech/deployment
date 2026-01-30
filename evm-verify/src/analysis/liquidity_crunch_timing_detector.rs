use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityCrunchTimingVulnerability {
    InsufficientReserves { description: String, location: usize, confidence: f32 },
    NoWithdrawalLimit { description: String, location: usize },
    SimultaneousExitRisk { description: String, location: usize },
}

pub struct LiquidityCrunchTimingDetector {
    bytecode: Vec<u8>,
}

impl LiquidityCrunchTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityCrunchTimingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect withdrawal functions
        if self.has_withdrawal_function() {
            if !self.checks_liquidity_reserves() {
                vulnerabilities.push(LiquidityCrunchTimingVulnerability::InsufficientReserves {
                    description: "Withdrawal doesn't check reserves - liquidity crunch during simultaneous exits".to_string(),
                    location: 0,
                    confidence: 0.80,
                });
            }
            
            if !self.has_withdrawal_limits() {
                vulnerabilities.push(LiquidityCrunchTimingVulnerability::NoWithdrawalLimit {
                    description: "No withdrawal rate limits - vulnerable to coordinated exit".to_string(),
                    location: 0,
                });
            }
            
            if self.uses_spot_balance_check() {
                vulnerabilities.push(LiquidityCrunchTimingVulnerability::SimultaneousExitRisk {
                    description: "Uses spot balance check - simultaneous exits can drain reserves".to_string(),
                    location: 0,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_withdrawal_function(&self) -> bool {
        // CALL or TRANSFER patterns
        self.bytecode.iter().any(|&b| b == 0xF1 || b == 0xF0)
    }
    
    fn checks_liquidity_reserves(&self) -> bool {
        // BALANCE opcode + comparison
        let has_balance = self.bytecode.iter().any(|&b| b == 0x31); // BALANCE
        let has_comparison = self.bytecode.iter().any(|&b| b == 0x10 || b == 0x11); // LT/GT
        has_balance && has_comparison
    }
    
    fn has_withdrawal_limits(&self) -> bool {
        // Time-based or amount-based limits
        let has_timestamp = self.bytecode.iter().any(|&b| b == 0x42);
        let has_gt_check = self.bytecode.iter().filter(|&&b| b == 0x11).count() > 2;
        has_timestamp || has_gt_check
    }
    
    fn uses_spot_balance_check(&self) -> bool {
        // BALANCE without historical tracking
        let balance_count = self.bytecode.iter().filter(|&&b| b == 0x31).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        balance_count > 0 && sload_count < 2
    }
}
