use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveragePoolVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CoveragePoolLiquidityDrainDetector {
    bytecode: Vec<u8>,
}

impl CoveragePoolLiquidityDrainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CoveragePoolVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_uncapped_claim_payout());
        vulnerabilities.extend(self.detect_simultaneous_claim_race());
        vulnerabilities.extend(self.detect_reserve_ratio_bypass());

        vulnerabilities
    }

    fn detect_uncapped_claim_payout(&self) -> Vec<CoveragePoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x03 { // SUB (pool balance reduction)
                let window_end = (pc + 40).min(self.bytecode.len());
                let has_transfer = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0xF1 | 0x55));
                
                if has_transfer {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let window = &self.bytecode[start..pc];
                    
                    let has_pool_balance = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                    let has_max_payout_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_pool_balance && !has_max_payout_check {
                        vulns.push(CoveragePoolVulnerability {
                            pc,
                            vulnerability_type: "UncappedClaimPayout".to_string(),
                            description: format!(
                                "Claim payout at PC {} withdraws from pool without maximum limit. Attack: submit claim for entire \
                                pool balance, draining all coverage liquidity. Missing: per-claim cap (e.g., 10% of pool), maximum \
                                payout per event, reserve protection. Single malicious claim can render protocol insolvent, \
                                leaving other policyholders unprotected.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_simultaneous_claim_race(&self) -> Vec<CoveragePoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (claim processing)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_claim_check = window.iter().any(|&b| b == 0x54); // SLOAD (claim state)
                
                if has_claim_check {
                    let has_reentrancy_lock = window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x15); // SLOAD + ISZERO
                    let has_claim_processed_flag = window.iter().filter(|&&b| b == 0x55).count() >= 2; // Multiple SSTORE
                    
                    if !has_reentrancy_lock && !has_claim_processed_flag {
                        vulns.push(CoveragePoolVulnerability {
                            pc,
                            vulnerability_type: "SimultaneousClaimRace".to_string(),
                            description: format!(
                                "Claim processing at PC {} vulnerable to simultaneous claim race condition. Attack: multiple \
                                valid claimants submit in same block, each checking pool has funds, all approved, total payout \
                                exceeds pool. First claims succeed, last ones fail/drain pool below safe threshold. Missing: \
                                atomic claim queue, total pending claim tracking, reserve buffer. Enables pool insolvency.",
                                pc
                            ),
                            confidence: 0.85,
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

    fn detect_reserve_ratio_bypass(&self) -> Vec<CoveragePoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 || opcode == 0x05 { // DIV, SDIV (ratio calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pool_balance = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                let has_total_coverage = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_pool_balance && has_total_coverage {
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_minimum_ratio = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_payout_blocking = forward.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if !has_minimum_ratio || !has_payout_blocking {
                        vulns.push(CoveragePoolVulnerability {
                            pc,
                            vulnerability_type: "ReserveRatioBypass".to_string(),
                            description: format!(
                                "Reserve ratio check at PC {} insufficiently enforced. Pool allows payouts reducing reserves \
                                below safe solvency threshold. Example: pool has 100 ETH coverage, 80 ETH deposited, should \
                                maintain 50% reserve but allows payout to 30 ETH. Missing: minimum reserve ratio enforcement, \
                                payout rejection below threshold, emergency reserve protection. Pool becomes insolvent.",
                                pc
                            ),
                            confidence: 0.87,
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
