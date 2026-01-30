/// Oracle Finality Assumption Detector
/// Detects L2 oracles reading potentially unfinalized L1 state

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleFinalityVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct OracleFinalityAssumptionDetector {
    bytecode: Vec<u8>,
}

impl OracleFinalityAssumptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OracleFinalityVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_no_finality_delay());
        vulnerabilities.extend(self.detect_optimistic_oracle_assumption());
        vulnerabilities.extend(self.detect_cross_chain_timestamp_issue());
        vulnerabilities
    }

    fn detect_no_finality_delay(&self) -> Vec<OracleFinalityVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            if self.is_oracle_call(pc) {
                if !self.has_finality_delay_check(pc, 200) && !self.has_chainid_conditional(pc, 150) {
                    vulnerabilities.push(OracleFinalityVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: format!(
                            "Oracle at PC {} doesn't check L1 finality delay. \
                            On L2, oracle may read unfinalized L1 state that can be reorged.",
                            pc
                        ),
                        exploit_scenario:
                            "Unfinalized Oracle Reorg Attack:\n\
                             1. L2 oracle reads L1 price feed at block N\n\
                             2. L1 block N is not yet finalized (12+ minutes on Ethereum)\n\
                             3. User borrows max based on oracle price from block N\n\
                             4. L1 block N gets reorged\n\
                             5. New block N' has different price\n\
                             6. L2 oracle updates to block N' price\n\
                             7. User's position is now underwater\n\
                             8. User already withdrew, protocol holds the loss\n\n\
                             Optimism/Arbitrum fix:\n\
                             uint256 constant L1_FINALITY_DELAY = 64; // ~13 min\n\
                             \n\
                             function getPrice() returns (uint256) {\n\
                                 (, int256 price, , uint256 l1Timestamp, ) = oracle.latestRoundData();\n\
                                 require(\n\
                                     block.timestamp - l1Timestamp >= L1_FINALITY_DELAY,\n\
                                     'L1 data not finalized'\n\
                                 );\n\
                                 return uint256(price);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_optimistic_oracle_assumption(&self) -> Vec<OracleFinalityVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_oracle_call(pc) {
                if self.uses_oracle_immediately(pc, 80) {
                    vulnerabilities.push(OracleFinalityVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Oracle value at PC {} is used immediately without any delay. \
                            Optimistic oracles can be disputed, causing retroactive price changes.",
                            pc
                        ),
                        exploit_scenario:
                            "Optimistic Oracle Dispute Attack:\n\
                             1. Protocol uses optimistic oracle (UMA, Tellor)\n\
                             2. Oracle posts price: ETH = $2000\n\
                             3. Protocol immediately uses price for liquidations\n\
                             4. User gets liquidated at $2000 price\n\
                             5. Oracle gets disputed (price was wrong)\n\
                             6. After dispute period, correct price: ETH = $2100\n\
                             7. User was wrongly liquidated\n\
                             8. No way to reverse the liquidation\n\n\
                             Fix:\n\
                             uint256 constant DISPUTE_PERIOD = 2 hours;\n\
                             \n\
                             mapping(bytes32 => OracleData) public oracleData;\n\
                             \n\
                             function useOracle(bytes32 priceId) {\n\
                                 OracleData memory data = oracleData[priceId];\n\
                                 require(\n\
                                     block.timestamp >= data.timestamp + DISPUTE_PERIOD,\n\
                                     'Oracle in dispute period'\n\
                                 );\n\
                                 // Now safe to use\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_cross_chain_timestamp_issue(&self) -> Vec<OracleFinalityVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(180) {
            if self.is_oracle_call(pc) {
                if self.has_timestamp_comparison(pc, 100) {
                    if !self.has_block_timestamp_sanity_check(pc, 150) {
                        vulnerabilities.push(OracleFinalityVulnerability {
                            severity: SecuritySeverity::Medium,
                            confidence: 0.65,
                            description: format!(
                                "Oracle timestamp comparison at PC {} doesn't account for \
                                L1/L2 block time differences. Can lead to stale data acceptance.",
                                pc
                            ),
                            exploit_scenario:
                                "Cross-Chain Timestamp Drift:\n\
                                 1. L1 block time: ~12 seconds\n\
                                 2. L2 block time: ~2 seconds\n\
                                 3. L2 oracle checks: require(timestamp > block.timestamp - 1 hour)\n\
                                 4. L1 oracle updated 50 minutes ago\n\
                                 5. Check passes on L2 (50 min < 1 hour)\n\
                                 6. But L1 is 250 blocks old (50 min / 12 sec)\n\
                                 7. In that time, price moved significantly\n\
                                 8. L2 uses stale price for critical operations\n\n\
                                 Fix:\n\
                                 function checkOracleStale(uint256 oracleTimestamp) view {\n\
                                     uint256 maxAge = block.chainid == 1 ? 1 hours : 20 minutes;\n\
                                     require(\n\
                                         block.timestamp - oracleTimestamp <= maxAge,\n\
                                         'Oracle too stale'\n\
                                     );\n\
                                 }".to_string(),
                            location: pc,
                        });
                    }
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_oracle_call(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() { return false; }
        let oracle_selectors = [
            [0x50, 0xd2, 0x5b, 0xcd],  // latestAnswer
            [0xfe, 0xaf, 0x96, 0x8c],  // latestRoundData
        ];
        for selector in &oracle_selectors {
            if self.bytecode[pc..].windows(4).take(50).any(|w| w == selector) {
                return true;
            }
        }
        false
    }

    fn has_finality_delay_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in (i + 1)..(i + 20).min(end) {
                    if self.bytecode[j] == 0x03 { // SUB
                        for k in (j + 1)..(j + 15).min(end) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) { // LT/GT
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn has_chainid_conditional(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x46 { // CHAINID
                return true;
            }
        }
        false
    }

    fn uses_oracle_immediately(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut found_oracle_return = false;
        for i in pc..end {
            if matches!(self.bytecode[i], 0x01 | 0x02 | 0x03 | 0x04) { // Arithmetic
                found_oracle_return = true;
            }
            if found_oracle_return && self.bytecode[i] == 0x42 { // TIMESTAMP check
                return false; // Has delay
            }
        }
        found_oracle_return
    }

    fn has_timestamp_comparison(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in (i + 1)..(i + 10).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x14) { // LT/GT/EQ
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_block_timestamp_sanity_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        // Look for CHAINID followed by conditional logic
        for i in start..end {
            if self.bytecode[i] == 0x46 { // CHAINID
                for j in (i + 1)..(i + 30).min(end) {
                    if self.bytecode[j] == 0x57 { // JUMPI (conditional)
                        return true;
                    }
                }
            }
        }
        false
    }
}
