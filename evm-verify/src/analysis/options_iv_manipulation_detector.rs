/// Options IV Manipulation Detector
/// Detects implied volatility gaming in options protocols (Panoptic, Dopex, Lyra)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionsIVVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct OptionsIVManipulationDetector {
    bytecode: Vec<u8>,
}

impl OptionsIVManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OptionsIVVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unbounded_iv_calculation());
        vulnerabilities.extend(self.detect_spot_price_iv_manipulation());
        vulnerabilities.extend(self.detect_oracle_iv_gaming());
        vulnerabilities
    }

    fn detect_unbounded_iv_calculation(&self) -> Vec<OptionsIVVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_iv_calculation(pc) {
                if !self.has_iv_bounds_check(pc, 150) {
                    vulnerabilities.push(OptionsIVVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: format!(
                            "IV calculation at PC {} has no bounds checking. \
                            Extreme market conditions can cause IV to spike, making options mispriced.",
                            pc
                        ),
                        exploit_scenario:
                            "IV Spike Exploitation:\n\
                             1. Protocol calculates IV from realized volatility\n\
                             2. IV formula: sqrt(sum((returns)^2) / periods)\n\
                             3. Attacker manipulates spot price with large trade\n\
                             4. Price swing creates huge return datapoint\n\
                             5. IV spikes from 50% to 500%\n\
                             6. Option premiums become extremely expensive\n\
                             7. Attacker sold options before manipulation\n\
                             8. Attacker buys back options at inflated IV\n\
                             9. Attacker profits from IV manipulation\n\n\
                             Fix:\n\
                             uint256 constant MIN_IV = 10;  // 10%\n\
                             uint256 constant MAX_IV = 300; // 300%\n\
                             \n\
                             function calculateIV(uint256[] memory returns) returns (uint256) {\n\
                                 uint256 variance = 0;\n\
                                 for (uint i = 0; i < returns.length; i++) {\n\
                                     // Cap individual returns\n\
                                     uint256 cappedReturn = returns[i] > MAX_RETURN ? MAX_RETURN : returns[i];\n\
                                     variance += cappedReturn * cappedReturn;\n\
                                 }\n\
                                 uint256 iv = sqrt(variance / returns.length);\n\
                                 \n\
                                 // Clamp IV to reasonable bounds\n\
                                 if (iv < MIN_IV) return MIN_IV;\n\
                                 if (iv > MAX_IV) return MAX_IV;\n\
                                 return iv;\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_spot_price_iv_manipulation(&self) -> Vec<OptionsIVVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_price_fetch(pc) && self.is_iv_calculation_nearby(pc, 100) {
                if !self.has_twap_protection(pc, 200) {
                    vulnerabilities.push(OptionsIVVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: format!(
                            "IV calculation near PC {} uses spot price without TWAP protection. \
                            Flash loan attacks can manipulate IV via spot price manipulation.",
                            pc
                        ),
                        exploit_scenario:
                            "Flash Loan IV Manipulation:\n\
                             1. Options protocol uses Uniswap spot price for IV calc\n\
                             2. IV = f(price_volatility)\n\
                             3. Attacker takes flash loan of 100M USDC\n\
                             4. Attacker buys massive amount of ETH from Uniswap\n\
                             5. ETH price spikes 20% in the pool\n\
                             6. Protocol recalculates IV, sees high volatility\n\
                             7. IV increases from 80% to 200%\n\
                             8. Attacker buys options at old IV (80%)\n\
                             9. Attacker repays flash loan, price normalizes\n\
                             10. Attacker's options are now massively underpriced\n\n\
                             Panoptic-style fix:\n\
                             function calculateIV() returns (uint256) {\n\
                                 // Use TWAP, not spot\n\
                                 uint256 twapPrice = uniswapPool.observe([3600, 0]);\n\
                                 \n\
                                 // Calculate returns from TWAP prices\n\
                                 uint256[] memory twapReturns = new uint256[](24);\n\
                                 for (uint i = 0; i < 24; i++) {\n\
                                     twapReturns[i] = calculateHourlyReturn(i);\n\
                                 }\n\
                                 \n\
                                 return calculateIVFromReturns(twapReturns);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_oracle_iv_gaming(&self) -> Vec<OptionsIVVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_oracle_based_iv(pc) {
                if !self.has_iv_staleness_check(pc, 180) {
                    vulnerabilities.push(OptionsIVVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Oracle-based IV at PC {} doesn't check for staleness. \
                            Stale IV during high volatility allows arbitrage opportunities.",
                            pc
                        ),
                        exploit_scenario:
                            "Stale IV Oracle Attack:\n\
                             1. Protocol uses Deribit IV oracle (updates every 30 min)\n\
                             2. Black swan event: market crashes 15%\n\
                             3. Real IV spikes from 60% to 150%\n\
                             4. On-chain oracle still shows 60% (stale)\n\
                             5. Attacker buys options at 60% IV\n\
                             6. Oracle updates 20 minutes later to 150%\n\
                             7. Attacker's options are now worth 3x\n\
                             8. Attacker sells or exercises for profit\n\n\
                             Lyra-style fix:\n\
                             struct IVData {\n\
                                 uint128 impliedVol;\n\
                                 uint128 timestamp;\n\
                             }\n\
                             \n\
                             function getIV() returns (uint256) {\n\
                                 IVData memory ivData = ivOracle.latestIV();\n\
                                 \n\
                                 require(\n\
                                     block.timestamp - ivData.timestamp <= 10 minutes,\n\
                                     'IV too stale'\n\
                                 );\n\
                                 \n\
                                 // During high volatility, require fresher data\n\
                                 if (ivData.impliedVol > 100) {\n\
                                     require(\n\
                                         block.timestamp - ivData.timestamp <= 5 minutes,\n\
                                         'IV stale during high vol'\n\
                                     );\n\
                                 }\n\
                                 \n\
                                 return ivData.impliedVol;\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_iv_calculation(&self, pc: usize) -> bool {
        if pc + 80 >= self.bytecode.len() { return false; }
        // Look for sqrt-like patterns (IV involves square root)
        let mut has_exp = false;
        let mut has_div = false;
        for i in pc..(pc + 80).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x0a { has_exp = true; }    // EXP opcode
            if self.bytecode[i] == 0x04 { has_div = true; }    // DIV opcode
        }
        has_exp && has_div
    }

    fn has_iv_bounds_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if matches!(self.bytecode[i], 0x10 | 0x11) { // LT or GT
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd { return true; } // REVERT
                }
            }
        }
        false
    }

    fn is_price_fetch(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() { return false; }
        // Look for external call patterns (CALL, STATICCALL)
        for i in pc..(pc + 50).min(self.bytecode.len()) {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                return true;
            }
        }
        false
    }

    fn is_iv_calculation_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.is_iv_calculation(i) {
                return true;
            }
        }
        false
    }

    fn has_twap_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        // Look for time-related operations (TIMESTAMP) suggesting TWAP
        for i in start..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn is_oracle_based_iv(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        // Look for external call followed by IV-like arithmetic
        let mut has_external_call = false;
        let mut has_iv_arithmetic = false;
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                has_external_call = true;
            }
            if has_external_call && matches!(self.bytecode[i], 0x02 | 0x04) {
                has_iv_arithmetic = true;
            }
        }
        has_external_call && has_iv_arithmetic
    }

    fn has_iv_staleness_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        for i in pc..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in (i + 1)..(i + 20).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        return true;
                    }
                }
            }
        }
        false
    }
}
