use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimismDataFeeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OptimismL1DataFeeGriefingDetector {
    bytecode: Vec<u8>,
}

impl OptimismL1DataFeeGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OptimismDataFeeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_calldata_bloat_attack());
        vulnerabilities.extend(self.detect_l1_fee_manipulation());
        vulnerabilities.extend(self.detect_data_compression_bypass());

        vulnerabilities
    }

    fn detect_calldata_bloat_attack(&self) -> Vec<OptimismDataFeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x37 { // CALLDATACOPY (copying large calldata)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_size_param = window.iter().any(|&b| b == 0x36); // CALLDATASIZE
                
                if has_size_param {
                    let has_size_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_fee_check = window.iter().any(|&b| b == 0x48); // BASEFEE
                    
                    if !has_size_limit || !has_fee_check {
                        vulns.push(OptimismDataFeeVulnerability {
                            pc,
                            vulnerability_type: "CalldataBloatAttack".to_string(),
                            description: format!(
                                "Calldata copy at PC {} without size limits. On Optimism, L1 data fees charged based on calldata \
                                size. Attack: submit transaction with massive calldata, forcing contract to pay excessive L1 fees. \
                                Missing: maximum calldata size enforcement, caller-pays-gas model, data size validation. Enables \
                                griefing by inflating contract's L1 data costs through bloated transactions.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_l1_fee_manipulation(&self) -> Vec<OptimismDataFeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (state updates causing L1 data)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_input = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_user_input {
                    let has_l1_gas_oracle = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // External call to gas oracle
                    let has_fee_refund = window.iter().any(|&b| b == 0x34); // CALLVALUE
                    
                    if !has_l1_gas_oracle || !has_fee_refund {
                        vulns.push(OptimismDataFeeVulnerability {
                            pc,
                            vulnerability_type: "L1FeeManipulation".to_string(),
                            description: format!(
                                "State update at PC {} doesn't account for Optimism L1 data fees. User can trigger expensive L1 \
                                data posting without paying proportional fees. Attack: force contract to post large state updates \
                                to L1, draining contract's ETH. Missing: L1 gas price oracle integration, dynamic fee calculation, \
                                refund mechanism. Contract subsidizes attacker's L1 data costs.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_data_compression_bypass(&self) -> Vec<OptimismDataFeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (reading calldata)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_event = window.iter().any(|&b| matches!(b, 0xA0..=0xA4)); // LOG operations
                
                if has_event {
                    let has_compression = window.iter().any(|&b| b == 0x1B); // SHL/SHR (bit packing)
                    let has_encoding_optimization = window.iter().any(|&b| b == 0x16); // AND (masking)
                    
                    if !has_compression && !has_encoding_optimization {
                        vulns.push(OptimismDataFeeVulnerability {
                            pc,
                            vulnerability_type: "DataCompressionBypass".to_string(),
                            description: format!(
                                "Data handling at PC {} uses uncompressed calldata on Optimism. L1 data fees proportional to size, \
                                but contract doesn't optimize encoding. Missing: RLP compression, bit packing, zero-byte optimization. \
                                Example: storing address as bytes32 instead of bytes20, or using unoptimized ABI encoding. Wastes \
                                L1 data fees by 25-50% compared to optimized encoding. Should use calldata compression strategies.",
                                pc
                            ),
                            confidence: 0.83,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
