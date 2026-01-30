use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC7641Vulnerability {
    FlashLoanRevenueClaimExploit { description: String, location: usize, confidence: f32 },
    RevenueFrontrunning { description: String, location: usize, confidence: f32 },
}

pub struct ERC7641RevenueDistributionDetector {
    bytecode: Vec<u8>,
}

impl ERC7641RevenueDistributionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC7641Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // ERC-7641: Revenue Distribution Token
        // Token holders receive revenue proportional to holdings
        // Risk: Flash loan to claim revenue without holding long-term
        
        for i in 0..self.bytecode.len().saturating_sub(110) {
            let section = &self.bytecode[i..std::cmp::min(i + 110, self.bytecode.len())];
            
            // Pattern: Revenue claim without minimum holding period
            let has_revenue_claim = section.windows(10).any(|w| {
                w.contains(&0x54) && // SLOAD (balance)
                w.contains(&0x04) && // DIV (calculate share)
                w.contains(&0xF1)    // CALL (transfer revenue)
            });
            
            let no_holding_check = !section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (acquisition time)
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x03) && // SUB (holding duration)
                w.contains(&0x10)    // LT (check minimum)
            });
            
            if has_revenue_claim && no_holding_check {
                vulnerabilities.push(ERC7641Vulnerability::FlashLoanRevenueClaimExploit {
                    description: format!("ERC-7641 flash loan revenue claim at PC {}. Attack: 1) Flash loan 1M tokens, 2) Call claimRevenue() → receive revenue proportional to 1M tokens, 3) Repay flash loan same tx. Cost = flash loan fee (0.09%). Profit = accumulated revenue. Example: $100k revenue accumulated → attacker claims proportional share with no long-term holding. Mitigation: Snapshot-based revenue (claim based on avg balance over epoch), OR minimum holding period (7 days).", i),
                    location: i,
                    confidence: 0.92,
                });
            }
            
            // Pattern: Revenue accrual without snapshot mechanism
            let has_accrual = section.windows(8).any(|w| {
                w.contains(&0x01) && // ADD (accumulate revenue)
                w.contains(&0x55)    // SSTORE
            });
            
            let no_snapshot = !section.windows(15).any(|w| {
                w.contains(&0x20) && // SHA3 (snapshot key)
                w.contains(&0x54)    // SLOAD (snapshot balance)
            });
            
            if has_accrual && no_snapshot {
                vulnerabilities.push(ERC7641Vulnerability::RevenueFrontrunning {
                    description: format!("Revenue distribution frontrunning at PC {}. When revenue added: 1) Bot detects addRevenue() tx in mempool, 2) Frontrun with buy, 3) Revenue distributes, 4) Immediately sell. Example: Protocol adds $50k revenue → bot buys 10% supply → receives $5k → sells tokens. Losses: Organic holders diluted, bot extracts value. Mitigation: Time-weighted snapshot (avg balance over last 24h), block-delay for new holders (1-block delay before revenue eligibility).", i),
                    location: i,
                    confidence: 0.88,
                });
            }
        }
        
        vulnerabilities
    }
}
