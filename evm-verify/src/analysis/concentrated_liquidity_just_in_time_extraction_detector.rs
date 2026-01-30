use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcentratedLiquidityJitExtractionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ConcentratedLiquidityJustInTimeExtractionDetector {
    bytecode: Vec<u8>,
}

impl ConcentratedLiquidityJustInTimeExtractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ConcentratedLiquidityJitExtractionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_jit_liquidity_sandwich());
        vulnerabilities.extend(self.detect_tick_manipulation_mev());
        vulnerabilities.extend(self.detect_range_order_frontrun());
        vulnerabilities
    }

    fn detect_jit_liquidity_sandwich(&self) -> Vec<ConcentratedLiquidityJitExtractionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (mint concentrated liquidity)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_tick_params = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 4;
                if has_tick_params {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let has_time_lock = self.bytecode[pc..window_end].iter().any(|&b| b == 0x42);
                    if !has_time_lock {
                        vulns.push(ConcentratedLiquidityJitExtractionVulnerability {
                            pc, vulnerability_type: "JitLiquiditySandwich".to_string(),
                            description: format!("Uniswap V3 concentrated liquidity mint at PC {} allows JIT liquidity sandwich attack. Attack: MEV bot sees large swap in mempool, frontruns by minting liquidity in exact tick range swap will use, captures all fees, backruns by removing liquidity. Real attack: victim swaps 100 ETH → USDC through tick range [1000, 1100], MEV bot frontruns minting max liquidity at ticks [1000, 1100], swap executes paying fees to bot's position, bot immediately burns position keeping fees. Example: victim's swap generates $1000 fees, normally distributed among all LPs in range, JIT bot captures 90% by providing 10x more liquidity just-in-time. Missing: minimum liquidity duration, anti-JIT mechanisms. Should implement: require liquidity locked for N blocks before earning fees, or penalize immediate withdrawals. Fix: protocols using V3 should implement time-weighted position checks, reject transactions if liquidity added same block as swap.", pc),
                            confidence: 0.89,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_tick_manipulation_mev(&self) -> Vec<ConcentratedLiquidityJitExtractionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (tick state read)
                let window_end = (pc + 100).min(self.bytecode.len());
                let uses_for_pricing = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x04).count() >= 2;
                if uses_for_pricing {
                    let validates_liquidity = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !validates_liquidity {
                        vulns.push(ConcentratedLiquidityJitExtractionVulnerability {
                            pc, vulnerability_type: "TickManipulationMev".to_string(),
                            description: format!("Tick-based pricing at PC {} vulnerable to concentrated liquidity manipulation. Attack: attacker adds/removes liquidity to manipulate pool.slot0() price reading, protocols using spot price for oracles see manipulated value. Real vulnerability: pool.slot0() returns current tick/sqrtPriceX96, concentrated liquidity means small swaps can move tick significantly, oracle reads manipulated price. Example: pool at tick 100000, attacker adds 100 ETH liquidity at tight range [100000, 100001], swaps 1 ETH pushing price to tick 100001, protocol reads inflated price, attacker arbitrages. Missing: use time-weighted average price (TWAP), not spot price. Should implement: observe(secondsAgo) to get TWAP, typically 30-minute window. Fix: never use slot0() for pricing, always use observe() with sufficient history.", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_range_order_frontrun(&self) -> Vec<ConcentratedLiquidityJitExtractionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (position creation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_range_params = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if has_range_params {
                    let has_price_validation = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_price_validation {
                        vulns.push(ConcentratedLiquidityJitExtractionVulnerability {
                            pc, vulnerability_type: "RangeOrderFrontrun".to_string(),
                            description: format!("Range order position at PC {} lacks price bounds, allowing frontrun extraction. Attack: user places limit order as concentrated LP position at specific tick range, MEV bot sees pending position, frontruns by moving price through range extracting all liquidity. Real attack: user creates range order to sell ETH between $2000-$2010, MEV bot sees pending tx, frontruns with swap moving price from $1999 to $2011, user's position executes filling at unfavorable price, bot backruns profiting. Example: limit sell 10 ETH at $2000-$2010 range, bot manipulates price to $2010, position fills entirely at $2000 (bottom of range instead of top), user loses $100, bot gains. Missing: require price hasn't moved significantly in recent blocks. Fix: implement slippage protection, check slot0().tick within expected range before position creation, add deadline parameter.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
