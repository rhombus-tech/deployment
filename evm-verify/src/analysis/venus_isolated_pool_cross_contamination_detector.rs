use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VenusIsolatedPoolVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VenusIsolatedPoolCrossContaminationDetector {
    bytecode: Vec<u8>,
}

impl VenusIsolatedPoolCrossContaminationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VenusIsolatedPoolVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_cross_pool_collateral_leak());
        vulnerabilities.extend(self.detect_shared_comptroller_attack());
        vulnerabilities.extend(self.detect_reward_distribution_cross_pool());

        vulnerabilities
    }

    fn detect_cross_pool_collateral_leak(&self) -> Vec<VenusIsolatedPoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (collateral check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_borrow_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_multiple_pools = window.iter().filter(|&&b| b == 0x20).count() >= 2; // Multiple KECCAK256
                
                if has_borrow_check && has_multiple_pools {
                    let has_pool_isolation = window.iter().any(|&b| b == 0x14); // EQ (pool ID check)
                    let has_cross_pool_prevention = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    
                    if !has_pool_isolation || !has_cross_pool_prevention {
                        vulns.push(VenusIsolatedPoolVulnerability {
                            pc,
                            vulnerability_type: "CrossPoolCollateralLeak".to_string(),
                            description: format!(
                                "Borrow check at PC {} doesn't enforce pool isolation. Venus isolated pools should prevent collateral in Pool A \
                                from backing borrows in Pool B. Attack: deposit collateral in safe Pool A (blue-chip assets), borrow from risky \
                                Pool B (shitcoins), Pool B defaults, Pool A depositors lose funds. Isolation broken. Missing: strict pool ID validation, \
                                collateral can only back same-pool borrows, cross-pool borrow prevention. Should validate: collateral.poolId == borrow.poolId.",
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

    fn detect_shared_comptroller_attack(&self) -> Vec<VenusIsolatedPoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (comptroller state)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_function = window.iter().any(|&b| b == 0x33); // CALLER (admin check)
                let has_global_parameter = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_admin_function && has_global_parameter {
                    let has_pool_specific_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    
                    if !has_pool_specific_check {
                        vulns.push(VenusIsolatedPoolVulnerability {
                            pc,
                            vulnerability_type: "SharedComptrollerAttack".to_string(),
                            description: format!(
                                "Comptroller update at PC {} applies globally across isolated pools. Attack: admin sets closeFactorMantissa for one \
                                risky pool, parameter applies to all pools, safe pools now have unsafe liquidation parameters. Or: oracle updates \
                                affect all pools simultaneously, causing cascade liquidations. Missing: per-pool parameter storage, pool-specific \
                                comptroller instances, parameter isolation. Should maintain separate comptroller state per isolated pool.",
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

    fn detect_reward_distribution_cross_pool(&self) -> Vec<VenusIsolatedPoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (reward claim)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_reward_calc = window.iter().any(|&b| b == 0x02); // MUL (reward calculation)
                let has_pool_interaction = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_reward_calc && has_pool_interaction {
                    let has_pool_reward_isolation = window.iter().any(|&b| b == 0x20); // KECCAK256 (pool-specific slot)
                    let has_cross_pool_check = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    
                    if !has_pool_reward_isolation {
                        vulns.push(VenusIsolatedPoolVulnerability {
                            pc,
                            vulnerability_type: "RewardDistributionCrossPool".to_string(),
                            description: format!(
                                "Reward distribution at PC {} doesn't isolate pool rewards. Attack: participate in risky Pool B, claim rewards funded \
                                by safe Pool A, Pool B goes bad, attacker extracted Pool A's rewards without Pool A's risk. Or: manipulate Pool B \
                                TVL to inflate reward share, drain rewards meant for Pool A users. Missing: per-pool reward accounting, isolated reward \
                                budgets, pool-specific reward claims. Should separate: poolA.rewards and poolB.rewards completely.",
                                pc
                            ),
                            confidence: 0.84,
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
