use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimismL1GasPriceOracleVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OptimismL1GasPriceOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl OptimismL1GasPriceOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OptimismL1GasPriceOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_stale_l1_base_fee());
        vulnerabilities.extend(self.detect_scalar_manipulation());
        vulnerabilities.extend(self.detect_overhead_cost_bypass());
        vulnerabilities
    }

    fn detect_stale_l1_base_fee(&self) -> Vec<OptimismL1GasPriceOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xFA { // STATICCALL (L1 oracle read)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let reads_oracle = self.bytecode[start..pc].iter().filter(|&&b| b == 0x60).count() >= 3;
                if reads_oracle {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let checks_timestamp = self.bytecode[pc..window_end].iter().any(|&b| b == 0x42);
                    if !checks_timestamp {
                        vulns.push(OptimismL1GasPriceOracleVulnerability {
                            pc, vulnerability_type: "StaleL1BaseFee".to_string(),
                            description: format!("Optimism L1 gas price oracle read at PC {} doesn't validate timestamp, vulnerable to stale data. Attack: OVM_GasPriceOracle.l1BaseFee() updated by sequencer asynchronously, can lag minutes behind actual L1 basefee, protocol trusts stale value. Real vulnerability: L1 basefee spikes 1000 gwei, oracle still reports 50 gwei cached value, protocol estimates L1 cost as 50*gasUsed, submits to L1 paying 1000*gasUsed, loses 20x expected. Example: bridge estimates withdrawal cost using oracle.l1BaseFee(), user pays L2 fee based on 50 gwei, actual L1 submission costs 1000 gwei, bridge subsidizes 95% of cost. Missing: check block.timestamp - oracle.lastUpdateTime < MAX_STALENESS. Should implement: require(block.timestamp - l1FeeOracle.lastUpdateTimestamp() < 5 minutes). Fix: use multiple L1 fee sources, implement TWAP over L1 basefee, add staleness circuit breaker.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_scalar_manipulation(&self) -> Vec<OptimismL1GasPriceOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x02 { // MUL (scalar * l1Fee calculation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_oracle_call = self.bytecode[start..pc].iter().any(|&b| b == 0xFA);
                if has_oracle_call {
                    let validates_scalar = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !validates_scalar {
                        vulns.push(OptimismL1GasPriceOracleVulnerability {
                            pc, vulnerability_type: "ScalarManipulation".to_string(),
                            description: format!("L1 fee calculation at PC {} uses oracle scalar without bounds validation, sequencer can manipulate. Attack: Optimism L1 fee = (l1GasUsed * l1BaseFee * scalar) / 1e6, sequencer controls scalar parameter, can set to extreme values. Real vulnerability: formula l1Fee = tx.data.length * 16 * l1BaseFee * scalar, if scalar = 1000000 instead of expected 1.0-2.0 range, fees inflate 500000x. Example: protocol calculates expected L1 cost for withdrawal, oracle.scalar() returns 1000000, user charged $1M for $2 withdrawal. Missing: require(scalar >= MIN_SCALAR && scalar <= MAX_SCALAR). Should implement: uint256 scalar = oracle.scalar(); require(scalar > 0 && scalar < 10e6, 'ScalarOutOfBounds'). Fix: hardcode expected scalar range, use multiple oracle sources for validation.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_overhead_cost_bypass(&self) -> Vec<OptimismL1GasPriceOracleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ADD (overhead + gasUsed)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_overhead_read = self.bytecode[start..pc].iter().filter(|&&b| b == 0xFA).count() >= 1;
                if has_overhead_read {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let validates_overhead = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x11).count() >= 1;
                    if !validates_overhead {
                        vulns.push(OptimismL1GasPriceOracleVulnerability {
                            pc, vulnerability_type: "OverheadCostBypass".to_string(),
                            description: format!("L1 overhead calculation at PC {} doesn't validate overhead parameter, allowing cost bypass. Attack: Optimism charges L1 DA cost as (overhead + compressedTxSize) * l1BaseFee, overhead parameter controlled by sequencer, setting to 0 eliminates base cost. Real vulnerability: l1Fee = (oracle.overhead() + tx.data.length) * l1BaseFee, if overhead = 0 when should be 2100 (fixed cost per tx), protocol underpays L1 costs by 2100 gas per tx. Example: protocol submits 1000 txs to L1, expects overhead of 2100 each = 2.1M gas, oracle.overhead() = 0, protocol pays only for calldata, shortfall = 2.1M gas. Missing: validate overhead in expected range, typically 2100-3000. Fix: require(overhead >= 2100 && overhead <= 5000), or use hardcoded overhead value instead of oracle.", pc),
                            confidence: 0.79,
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
