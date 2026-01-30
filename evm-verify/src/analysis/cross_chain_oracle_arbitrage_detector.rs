/// Cross-Chain Oracle Arbitrage Detector
/// Detects vulnerabilities when contracts use price oracles across different chains
/// without accounting for:
/// 1. Block time differences (L1 vs L2 finality)
/// 2. Oracle update frequency differences
/// 3. Cross-chain price discrepancies
///
/// Attack Vector: Exploiter sees price change on L1, front-runs L2 oracle update
/// Examples: Chainlink on Ethereum vs Arbitrum/Optimism, price lag exploitation
///
/// Real exploits: Cross-chain lending protocols lose millions when L2 prices lag L1

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainOracleVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub issue_type: CrossChainOracleIssueType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossChainOracleIssueType {
    NoChainIdCheck,                    // Doesn't verify which chain oracle is on
    NoTimestampComparison,             // Doesn't compare timestamps across chains
    NoPriceDeviationCheck,             // Doesn't check for cross-chain price deviation
    SingleChainOracleAssumption,       // Assumes oracle behaves same on all chains
    NoFinalityCheck,                   // Doesn't wait for L1 finality on L2
}

pub struct CrossChainOracleArbitrageDetector {
    bytecode: Vec<u8>,
}

impl CrossChainOracleArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Oracle call without chain ID verification
        vulnerabilities.extend(self.detect_no_chain_id_check());

        // Pattern 2: Price comparison across chains without timestamp check
        vulnerabilities.extend(self.detect_no_timestamp_comparison());

        // Pattern 3: Direct oracle usage without price deviation bounds
        vulnerabilities.extend(self.detect_no_price_deviation_check());

        // Pattern 4: L2 oracle usage without finality consideration
        vulnerabilities.extend(self.detect_no_finality_check());

        vulnerabilities
    }

    /// Detect: Oracle calls without checking chain ID
    fn detect_no_chain_id_check(&self) -> Vec<CrossChainOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(150) {
            // Look for Chainlink-style oracle calls (latestRoundData, latestAnswer)
            if self.is_oracle_price_call(pc) {
                // Check if there's a CHAINID opcode nearby (0x46)
                if !self.has_chainid_check_nearby(pc, 200) {
                    vulnerabilities.push(CrossChainOracleVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.90,
                        description: format!(
                            "CRITICAL: Oracle price fetch at PC {} does not verify chain ID. \
                            This contract is vulnerable to cross-chain oracle arbitrage if deployed \
                            on multiple chains. Price discrepancies between L1/L2 can be exploited.",
                            pc
                        ),
                        exploit_scenario:
                            "Cross-Chain Oracle Arbitrage:\n\
                             1. ETH price on Ethereum: $2000 (up to date)\n\
                             2. ETH price on Arbitrum: $1950 (5 min lag)\n\
                             3. Attacker sees L1 price increase\n\
                             4. Attacker borrows max ETH on Arbitrum at old price\n\
                             5. Oracle updates on Arbitrum to $2000\n\
                             6. Attacker's collateral value jumps\n\
                             7. Attacker withdraws, protocol loses funds\n\n\
                             This is EXTREMELY common in cross-chain DeFi!\n\n\
                             Fix: Always verify oracle is appropriate for the chain:\n\
                             uint256 chainId = block.chainid;\n\
                             if (chainId == 1) {\n\
                                 // Use L1 oracle\n\
                                 price = l1Oracle.latestAnswer();\n\
                             } else if (chainId == 42161) {\n\
                                 // Use L2 oracle with sequencer uptime check\n\
                                 require(sequencerUptimeFeed.latestAnswer() > 0, 'Sequencer down');\n\
                                 price = l2Oracle.latestAnswer();\n\
                             }\n\
                             // Add price freshness checks!".to_string(),
                        location: pc,
                        issue_type: CrossChainOracleIssueType::NoChainIdCheck,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Price comparisons without timestamp validation
    fn detect_no_timestamp_comparison(&self) -> Vec<CrossChainOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(300) {
            // Look for multiple oracle calls (suggests price comparison)
            if self.is_oracle_price_call(pc) {
                if let Some(second_oracle_pc) = self.find_next_oracle_call(pc + 50, 200) {
                    // Check if there's timestamp comparison
                    if !self.has_timestamp_comparison_between(pc, second_oracle_pc + 100) {
                        vulnerabilities.push(CrossChainOracleVulnerability {
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: format!(
                                "Contract compares prices from multiple oracles (PC {} and PC {}) \
                                without validating timestamps. Cross-chain oracle updates can be \
                                minutes apart, allowing arbitrage during the lag window.",
                                pc, second_oracle_pc
                            ),
                            exploit_scenario:
                                "Timestamp Lag Arbitrage:\n\
                                 1. Protocol uses oracle1 (L1) and oracle2 (L2)\n\
                                 2. L1 oracle updates: BTC = $42,000 at timestamp T\n\
                                 3. L2 oracle still shows: BTC = $41,500 at timestamp T-300\n\
                                 4. Attacker executes trades based on stale L2 price\n\
                                 5. By the time L2 updates, attacker has extracted value\n\n\
                                 Fix: Validate timestamp deltas:\n\
                                 (, int256 price1, , uint256 updatedAt1, ) = oracle1.latestRoundData();\n\
                                 (, int256 price2, , uint256 updatedAt2, ) = oracle2.latestRoundData();\n\
                                 require(updatedAt1 >= block.timestamp - 3600, 'Oracle1 stale');\n\
                                 require(updatedAt2 >= block.timestamp - 3600, 'Oracle2 stale');\n\
                                 require(abs(updatedAt1 - updatedAt2) < 300, 'Oracle time delta too large');".to_string(),
                            location: pc,
                            issue_type: CrossChainOracleIssueType::NoTimestampComparison,
                        });
                    }
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: Oracle usage without price deviation bounds
    fn detect_no_price_deviation_check(&self) -> Vec<CrossChainOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_oracle_price_call(pc) {
                // Check if price is used in arithmetic without deviation check
                if self.has_price_arithmetic_without_bounds(pc, 150) {
                    vulnerabilities.push(CrossChainOracleVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Oracle price at PC {} is used in calculations without checking for \
                            unreasonable cross-chain price deviations. Attackers can exploit \
                            temporary discrepancies during cross-chain oracle propagation.",
                            pc
                        ),
                        exploit_scenario:
                            "Price Deviation Exploitation:\n\
                             1. Normal state: ETH on L1 = $2000, L2 = $2000\n\
                             2. Flash crash on L1: ETH drops to $1800 briefly\n\
                             3. L1 oracle updates immediately to $1800\n\
                             4. L2 oracle hasn't updated yet (still $2000)\n\
                             5. Attacker liquidates on L1 at $1800\n\
                             6. Attacker borrows max on L2 at $2000 collateral value\n\
                             7. Oracle sync, L2 updates to $1800\n\
                             8. Attacker's position underwater but already withdrew\n\n\
                             Fix: Check price deviation:\n\
                             uint256 l1Price = l1Oracle.latestAnswer();\n\
                             uint256 l2Price = l2Oracle.latestAnswer();\n\
                             uint256 priceDiff = l1Price > l2Price ? l1Price - l2Price : l2Price - l1Price;\n\
                             uint256 deviationPct = (priceDiff * 10000) / l1Price;\n\
                             require(deviationPct < 500, 'Cross-chain price deviation > 5%');\n\
                             // Use conservative price (lower of the two for collateral)".to_string(),
                        location: pc,
                        issue_type: CrossChainOracleIssueType::NoPriceDeviationCheck,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    /// Detect: L2 oracle usage without L1 finality check
    fn detect_no_finality_check(&self) -> Vec<CrossChainOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            // Look for L2 sequencer uptime check (Chainlink pattern)
            if self.is_oracle_price_call(pc) {
                // Check if there's sequencer uptime check
                // Arbitrum/Optimism use sequencer uptime feed
                if !self.has_sequencer_check_before(pc, 150) {
                    vulnerabilities.push(CrossChainOracleVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.65,
                        description: format!(
                            "Oracle at PC {} may be on L2 but doesn't check sequencer uptime. \
                            During sequencer downtime, oracle prices are stale and can be exploited \
                            when sequencer comes back online.",
                            pc
                        ),
                        exploit_scenario:
                            "L2 Sequencer Downtime Exploit:\n\
                             1. Arbitrum sequencer goes down for 1 hour\n\
                             2. During downtime, oracle prices are frozen\n\
                             3. L1 prices change significantly (ETH +10%)\n\
                             4. Sequencer comes back online\n\
                             5. Attacker submits txs immediately with stale prices\n\
                             6. Attacker borrows/liquidates at old prices\n\
                             7. Oracle updates 30 seconds later\n\
                             8. Attacker has already extracted value\n\n\
                             This exploit has happened multiple times on Optimism/Arbitrum!\n\n\
                             Fix: Check L2 sequencer uptime:\n\
                             // For Arbitrum/Optimism\n\
                             (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();\n\
                             require(answer == 0, 'Sequencer is down');\n\
                             require(block.timestamp - startedAt <= GRACE_PERIOD, 'Sequencer recently restarted');\n\
                             // Now safe to use oracle\n\
                             price = priceFeed.latestAnswer();".to_string(),
                        location: pc,
                        issue_type: CrossChainOracleIssueType::NoFinalityCheck,
                    });
                }
            }

            pc += 1;
        }

        vulnerabilities
    }

    // Helper methods

    fn is_oracle_price_call(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() {
            return false;
        }
        
        // Chainlink latestAnswer: 0x50d25bcd
        // Chainlink latestRoundData: 0xfeaf968c
        // Common oracle methods
        let patterns = [
            [0x50, 0xd2, 0x5b, 0xcd],  // latestAnswer()
            [0xfe, 0xaf, 0x96, 0x8c],  // latestRoundData()
            [0x66, 0x8a, 0x0f, 0x02],  // latestTimestamp()
        ];

        for pattern in &patterns {
            if self.bytecode[pc..].windows(4).take(50).any(|w| w == pattern) {
                return true;
            }
        }

        false
    }

    fn has_chainid_check_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        for i in start..end {
            if self.bytecode[i] == 0x46 {  // CHAINID opcode
                return true;
            }
        }
        false
    }

    fn find_next_oracle_call(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        for i in start..end {
            if self.is_oracle_price_call(i) {
                return Some(i);
            }
        }
        None
    }

    fn has_timestamp_comparison_between(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        
        // Look for TIMESTAMP opcode (0x42) followed by comparison (LT, GT, EQ)
        for i in start..end.saturating_sub(10) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                // Check next few opcodes for comparison
                for j in (i + 1)..(i + 10).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11 | 0x12 | 0x13 | 0x14) {
                        // LT, GT, SLT, SGT, EQ
                        return true;
                    }
                }
            }
        }
        
        false
    }

    fn has_price_arithmetic_without_bounds(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        
        let mut has_arithmetic = false;
        let mut has_bounds_check = false;

        for i in pc..end {
            // Check for arithmetic operations
            if matches!(self.bytecode[i], 0x01 | 0x02 | 0x03 | 0x04) {  // ADD, SUB, MUL, DIV
                has_arithmetic = true;
            }
            
            // Check for bounds/comparison operations
            if matches!(self.bytecode[i], 0x10 | 0x11) {  // LT, GT
                // Look for REVERT nearby (suggests bounds check)
                for j in (i + 1)..(i + 20).min(end) {
                    if self.bytecode[j] == 0xfd {  // REVERT
                        has_bounds_check = true;
                        break;
                    }
                }
            }
        }

        has_arithmetic && !has_bounds_check
    }

    fn has_sequencer_check_before(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range);
        
        // Look for pattern suggesting sequencer uptime check
        // Typically involves external call followed by comparison and potential revert
        let mut has_external_call = false;
        let mut has_comparison = false;

        for i in start..pc {
            // Check for CALL/STATICCALL to external contract
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {  // CALL, STATICCALL
                has_external_call = true;
            }
            
            // Check for EQ comparison (checking sequencer answer == 0)
            if self.bytecode[i] == 0x14 && has_external_call {  // EQ
                has_comparison = true;
            }
        }

        has_external_call && has_comparison
    }
}
