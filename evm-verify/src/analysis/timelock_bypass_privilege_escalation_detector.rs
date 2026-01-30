use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelockBypassVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimelockBypassPrivilegeEscalationDetector {
    bytecode: Vec<u8>,
}

impl TimelockBypassPrivilegeEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TimelockBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_emergency_function_bypass());
        vulnerabilities.extend(self.detect_admin_role_escalation());
        vulnerabilities.extend(self.detect_timelock_cancellation_abuse());

        vulnerabilities
    }

    fn detect_emergency_function_bypass(&self) -> Vec<TimelockBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (privileged action)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_check = window.iter().any(|&b| b == 0x33); // CALLER
                let has_critical_action = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_admin_check && has_critical_action {
                    let has_timelock_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_delay_validation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_timelock_check || !has_delay_validation {
                        vulns.push(TimelockBypassVulnerability {
                            pc,
                            vulnerability_type: "EmergencyFunctionBypass".to_string(),
                            description: format!(
                                "Privileged action at PC {} bypasses timelock via emergency function. Admin can execute immediate \
                                changes claiming emergency, defeating timelock's purpose. Attack: upgrade to malicious implementation \
                                instantly, no community review. Missing: multi-sig requirement for emergency, post-action transparency, \
                                narrow emergency scope. Emergency powers should be restricted to truly urgent scenarios.",
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

    fn detect_admin_role_escalation(&self) -> Vec<TimelockBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (role assignment)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_role_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_caller_check = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_role_data && has_caller_check {
                    let has_timelock_delay = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_proposal_reference = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_timelock_delay || !has_proposal_reference {
                        vulns.push(TimelockBypassVulnerability {
                            pc,
                            vulnerability_type: "AdminRoleEscalation".to_string(),
                            description: format!(
                                "Role assignment at PC {} allows instant admin elevation. Existing admin can grant themselves \
                                timelock-bypassing roles immediately. Attack: admin grants self PROPOSER+EXECUTOR roles, executes \
                                transactions without delay. Missing: role change timelock, governance approval, role separation. \
                                Admin should not self-grant roles that bypass timelock protections.",
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

    fn detect_timelock_cancellation_abuse(&self) -> Vec<TimelockBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (canceling queued transaction)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_tx_id = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_tx_id {
                    let has_admin_only = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_governance_check = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let has_reason_logging = window.iter().any(|&b| matches!(b, 0xA0..=0xA4)); // LOG
                    
                    if has_admin_only && (!has_governance_check || !has_reason_logging) {
                        vulns.push(TimelockBypassVulnerability {
                            pc,
                            vulnerability_type: "TimelockCancellationAbuse".to_string(),
                            description: format!(
                                "Timelock cancellation at PC {} allows admin to censor proposals. Admin queues malicious action, \
                                community detects it, admin cancels before execution. Then resubmits during low-attention period. \
                                Missing: cancellation justification requirement, governance vote for cancellation, cancellation limits. \
                                Should prevent using cancel→requeue to bypass review periods.",
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
}
