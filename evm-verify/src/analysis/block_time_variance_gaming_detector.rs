use serde::{Deserialize, Serialize};

/// Block Time Variance Gaming Detector
/// 
/// PoS block times vary (12s target but can be 11-13s). Attackers can exploit this variance
/// for timing attacks on DeFi protocols that assume fixed block times.
///
/// Key Attacks:
/// 1. Exploit fast blocks for time-sensitive operations
/// 2. Game auctions by timing around block variance
/// 3. Manipulate TWAP by controlling which blocks have which prices
/// 4. DOS by waiting for slow blocks to execute
///
/// Real-World Impact:
/// - Affects all PoS chains (Ethereum, BSC, Polygon)
/// - Auction protocols particularly vulnerable

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTimeVarianceVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BlockTimeVarianceGamingDetector {
    bytecode: Vec<u8>,
}

impl BlockTimeVarianceGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlockTimeVarianceVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.has_fixed_block_time_assumption() {
            vulnerabilities.push(BlockTimeVarianceVulnerability {
                vulnerability_type: "Fixed Block Time Assumption".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Code assumes fixed block times, vulnerable to PoS variance".to_string(),
                confidence: 0.75,
            });
        }

        if let Some(loc) = self.has_auction_timing_vulnerability() {
            vulnerabilities.push(BlockTimeVarianceVulnerability {
                vulnerability_type: "Auction Timing Vulnerability".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Auction timing can be gamed using block time variance".to_string(),
                confidence: 0.80,
            });
        }

        vulnerabilities
    }

    fn has_fixed_block_time_assumption(&self) -> Option<usize> {
        // Look for: Timestamp arithmetic assuming fixed blocks (e.g., / 12)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x04 { // DIV
                // Check if dividing by common block time constant
                if let Some(&0x60) = self.bytecode.get(i.saturating_sub(2)) { // PUSH1
                    if let Some(&val) = self.bytecode.get(i.saturating_sub(1)) {
                        // Common block times: 12, 13, 14, 15 seconds
                        if (12..=15).contains(&val) {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_auction_timing_vulnerability(&self) -> Option<usize> {
        // Auction: TIMESTAMP comparison + no variance tolerance
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+15.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 { // GT/LT
                        // No tolerance = vulnerable
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
