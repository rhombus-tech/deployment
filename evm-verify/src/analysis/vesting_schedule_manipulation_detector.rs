use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingManipulationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VestingScheduleManipulationDetector {
    bytecode: Vec<u8>,
}

impl VestingScheduleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VestingManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_cliff_period_bypass());
        vulnerabilities.extend(self.detect_vesting_schedule_retroactive_change());
        vulnerabilities.extend(self.detect_early_unlock_privilege());

        vulnerabilities
    }

    fn detect_cliff_period_bypass(&self) -> Vec<VestingManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (cliff check)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_comparison = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_transfer = window.iter().any(|&b| matches!(b, 0x55 | 0xF1)); // SSTORE or CALL
                
                if has_comparison && has_transfer {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_admin_override = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    let has_jumpi = window.iter().any(|&b| b == 0x57); // JUMPI (conditional)
                    
                    if has_admin_override && !has_jumpi {
                        vulns.push(VestingManipulationVulnerability {
                            pc,
                            vulnerability_type: "CliffPeriodBypass".to_string(),
                            description: format!(
                                "Vesting cliff check at PC {} allows admin bypass. Privileged role can unlock tokens before \
                                cliff period, violating vesting agreement. Missing: immutable cliff enforcement, multi-sig \
                                requirement for early unlock, public transparency. Enables team to dump tokens on market \
                                before agreed schedule.",
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

    fn detect_vesting_schedule_retroactive_change(&self) -> Vec<VestingManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (updating schedule)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_timestamp_data = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_amount_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_timestamp_data || has_amount_data {
                    let has_beneficiary_check = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_timelock = window.windows(3).any(|w| w[0] == 0x42 && w[1] == 0x03); // TIMESTAMP - old_timestamp
                    
                    if has_beneficiary_check && !has_timelock {
                        vulns.push(VestingManipulationVulnerability {
                            pc,
                            vulnerability_type: "VestingScheduleRetroactiveChange".to_string(),
                            description: format!(
                                "Vesting schedule modification at PC {} without timelock protection. Admin can retroactively \
                                change vesting terms, extending cliff or reducing amounts. Missing: schedule immutability, \
                                beneficiary consent requirement, change delay period. Violates vesting commitments, \
                                allowing rug pull by extending unlock indefinitely.",
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

    fn detect_early_unlock_privilege(&self) -> Vec<VestingManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x14 { // EQ (checking privileged address)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_caller = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_caller {
                    let window_end = (pc + 70).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_unlock = forward_window.iter().any(|&b| matches!(b, 0x55 | 0xF1)); // SSTORE or CALL (transfer)
                    let has_timestamp_check = forward_window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if has_unlock && !has_timestamp_check {
                        vulns.push(VestingManipulationVulnerability {
                            pc,
                            vulnerability_type: "EarlyUnlockPrivilege".to_string(),
                            description: format!(
                                "Privileged early unlock at PC {} bypasses vesting schedule entirely. Admin whitelist can \
                                claim tokens immediately regardless of cliff or vesting period. Missing: timestamp validation \
                                for all withdrawals, uniform vesting enforcement, privilege limitation. Creates unfair \
                                advantage where insiders unlock early while others wait, enabling insider trading.",
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
}
