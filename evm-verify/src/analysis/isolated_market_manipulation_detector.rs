/// Isolated Market Manipulation Detector
/// Detects price manipulation in isolated lending markets (Aave V3, Euler, Silo)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedMarketManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct IsolatedMarketManipulationDetector {
    bytecode: Vec<u8>,
}

impl IsolatedMarketManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IsolatedMarketManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_isolated_oracle_manipulation());
        vulnerabilities.extend(self.detect_cross_market_isolation_bypass());
        vulnerabilities.extend(self.detect_liquidity_concentration_risk());
        vulnerabilities
    }

    fn detect_isolated_oracle_manipulation(&self) -> Vec<IsolatedMarketManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_isolated_market_operation(pc) {
                if !self.has_oracle_diversity_check(pc, 200) {
                    vulnerabilities.push(IsolatedMarketManipulationVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Isolated market at PC {} uses single oracle without diversity checks. \
                            Low-liquidity collateral can be manipulated to borrow against inflated values.",
                            pc
                        ),
                        exploit_scenario:
                            "Isolated Market Oracle Manipulation:\n\
                             1. Isolated market allows RARE_TOKEN as collateral\n\
                             2. RARE_TOKEN has $10K daily volume (low liquidity)\n\
                             3. Oracle uses single DEX price feed\n\
                             4. Attacker flash loans $1M USDC\n\
                             5. Attacker buys RARE_TOKEN, pumps price 10x\n\
                             6. Oracle reports inflated price\n\
                             7. Attacker deposits RARE_TOKEN as collateral\n\
                             8. Attacker borrows maximum against inflated value\n\
                             9. Attacker dumps RARE_TOKEN, price crashes\n\
                             10. Protocol holds bad debt from over-collateralized position\n\n\
                             Euler hack ($200M) used similar isolated market manipulation\n\n\
                             Fix:\n\
                             function validateIsolatedCollateral(address asset) {\n\
                                 // Require multiple independent oracles\n\
                                 require(oracleCount[asset] >= 3, 'Need 3+ oracles');\n\
                                 \n\
                                 uint256[] memory prices = new uint256[](oracleCount[asset]);\n\
                                 for (uint i = 0; i < oracleCount[asset]; i++) {\n\
                                     prices[i] = oracles[asset][i].getPrice();\n\
                                 }\n\
                                 \n\
                                 // Check price deviation\n\
                                 uint256 median = getMedian(prices);\n\
                                 for (uint i = 0; i < prices.length; i++) {\n\
                                     uint256 deviation = abs(prices[i] - median) * 10000 / median;\n\
                                     require(deviation < 500, 'Oracle deviation > 5%');\n\
                                 }\n\
                                 \n\
                                 // Check minimum liquidity\n\
                                 require(getDailyVolume(asset) >= MIN_LIQUIDITY, 'Insufficient liquidity');\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_cross_market_isolation_bypass(&self) -> Vec<IsolatedMarketManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(280) {
            if self.is_isolated_market_operation(pc) {
                if self.has_cross_market_calls(pc, 300) && !self.has_isolation_enforcement(pc, 300) {
                    vulnerabilities.push(IsolatedMarketManipulationVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Isolated market at PC {} can be bypassed via cross-market interactions. \
                            Risk contagion from isolated markets to main pool.",
                            pc
                        ),
                        exploit_scenario:
                            "Isolation Bypass Attack:\n\
                             1. Main market: USDC, ETH, WBTC (highly liquid)\n\
                             2. Isolated market: SHITCOIN (low liquidity, risky)\n\
                             3. Isolation supposed to prevent SHITCOIN risk affecting main market\n\
                             4. Attacker finds cross-market interaction bug\n\
                             5. Attacker borrows in isolated market against SHITCOIN\n\
                             6. Attacker uses those funds to borrow in main market\n\
                             7. SHITCOIN price crashes\n\
                             8. Bad debt from isolated market leaks into main market\n\
                             9. All lenders in main market affected\n\n\
                             Fix: Strict isolation enforcement:\n\
                             mapping(address => bool) public isIsolated;\n\
                             mapping(address => mapping(address => bool)) public isolatedBorrowAllowed;\n\
                             \n\
                             function borrow(address asset, uint256 amount) {\n\
                                 address[] memory userCollateral = getUserCollateral(msg.sender);\n\
                                 \n\
                                 bool hasIsolatedCollateral = false;\n\
                                 for (uint i = 0; i < userCollateral.length; i++) {\n\
                                     if (isIsolated[userCollateral[i]]) {\n\
                                         hasIsolatedCollateral = true;\n\
                                         // Can only borrow whitelisted assets\n\
                                         require(\n\
                                             isolatedBorrowAllowed[userCollateral[i]][asset],\n\
                                             'Asset not allowed with isolated collateral'\n\
                                         );\n\
                                     }\n\
                                 }\n\
                                 \n\
                                 // If using isolated collateral, cannot use other collateral\n\
                                 if (hasIsolatedCollateral) {\n\
                                     require(userCollateral.length == 1, 'Cannot mix isolated with other collateral');\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_liquidity_concentration_risk(&self) -> Vec<IsolatedMarketManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_isolated_market_operation(pc) {
                if !self.has_concentration_limits(pc, 180) {
                    vulnerabilities.push(IsolatedMarketManipulationVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Isolated market at PC {} doesn't limit position concentration. \
                            Single user can dominate market and manipulate rates.",
                            pc
                        ),
                        exploit_scenario:
                            "Liquidity Concentration Attack:\n\
                             1. Isolated market for TOKEN_X has $1M total supply\n\
                             2. No concentration limits\n\
                             3. Attacker deposits $900K of TOKEN_X (90% of market)\n\
                             4. Attacker borrows maximum against own collateral\n\
                             5. Utilization rate spikes to 95%\n\
                             6. Interest rates skyrocket\n\
                             7. Other users can't afford to borrow\n\
                             8. Attacker has monopoly control\n\
                             9. Can manipulate interest rates at will\n\n\
                             Fix:\n\
                             uint256 constant MAX_POSITION_PCT = 2000; // 20%\n\
                             \n\
                             function supply(address asset, uint256 amount) {\n\
                                 if (isIsolated[asset]) {\n\
                                     uint256 totalSupply = getTotalSupply(asset);\n\
                                     uint256 userSupply = getUserSupply(msg.sender, asset);\n\
                                     uint256 newPct = (userSupply + amount) * 10000 / (totalSupply + amount);\n\
                                     \n\
                                     require(\n\
                                         newPct <= MAX_POSITION_PCT,\n\
                                         'Position would exceed 20% of isolated market'\n\
                                     );\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_isolated_market_operation(&self, pc: usize) -> bool {
        if pc + 150 >= self.bytecode.len() { return false; }
        
        // Look for market isolation checks (multiple SLOADs suggesting market-specific logic)
        let mut sload_count = 0;
        for i in pc..(pc + 150).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { sload_count += 1; }
        }
        
        sload_count >= 3
    }

    fn has_oracle_diversity_check(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for multiple oracle calls (external calls)
        let mut external_calls = 0;
        for i in start..end {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) {
                external_calls += 1;
            }
        }
        
        external_calls >= 3 // Multiple oracles
    }

    fn has_cross_market_calls(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut call_count = 0;
        
        for i in pc..end {
            if matches!(self.bytecode[i], 0xf1 | 0xf2 | 0xf4) {
                call_count += 1;
            }
        }
        
        call_count >= 2
    }

    fn has_isolation_enforcement(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for EQ checks (checking isolation flag)
        for i in start..end {
            if self.bytecode[i] == 0x14 { // EQ
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd { return true; }
                }
            }
        }
        false
    }

    fn has_concentration_limits(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        
        // Look for percentage calculation (MUL + DIV pattern)
        let mut has_mul = false;
        let mut has_div = false;
        
        for i in start..end {
            if self.bytecode[i] == 0x02 { has_mul = true; }
            if has_mul && self.bytecode[i] == 0x04 { has_div = true; }
        }
        
        has_mul && has_div
    }
}
