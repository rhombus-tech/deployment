use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnosisSafeModuleVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GnosisSafeModulePrivilegeEscalationDetector {
    bytecode: Vec<u8>,
}

impl GnosisSafeModulePrivilegeEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GnosisSafeModuleVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_module_addition());
        vulnerabilities.extend(self.detect_module_delegatecall_abuse());
        vulnerabilities.extend(self.detect_module_removal_bypass());

        vulnerabilities
    }

    fn detect_unchecked_module_addition(&self) -> Vec<GnosisSafeModuleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (module registration)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_module_address = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_linked_list_update = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_module_address && has_linked_list_update {
                    let has_threshold_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_threshold_check && !has_timelock {
                        vulns.push(GnosisSafeModuleVulnerability {
                            pc,
                            vulnerability_type: "UncheckedModuleAddition".to_string(),
                            description: format!(
                                "Gnosis Safe module addition at PC {} lacks proper authorization checks. Attack: Safe modules have powerful delegatecall privileges to Safe's \
                                context, single owner can add malicious module without full multisig approval if threshold check missing. Malicious module can: (1) drain all Safe \
                                funds via delegatecall, (2) change ownership, (3) modify threshold to 1-of-N. Example: 3-of-5 Safe, malicious owner adds module that calls \
                                execTransactionFromModule with delegatecall to drain contract, bypasses other 4 owners. Real exploit: attacker compromises 1 key, adds module, \
                                steals funds. Missing: require N-of-M threshold for enableModule, timelock delay, module whitelist. Should enforce: enableModule requires same \
                                threshold as normal transactions, add 24-48h timelock for new modules, maintain approved module registry.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_module_delegatecall_abuse(&self) -> Vec<GnosisSafeModuleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF4 { // DELEGATECALL (from module)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_module_check = window.iter().any(|&b| b == 0x54); // SLOAD (module verification)
                
                if has_module_check {
                    let has_target_whitelist = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let has_function_selector_check = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256
                    
                    if !has_target_whitelist && !has_function_selector_check {
                        vulns.push(GnosisSafeModuleVulnerability {
                            pc,
                            vulnerability_type: "ModuleDelegatecallAbuse".to_string(),
                            description: format!(
                                "Module delegatecall at PC {} allows unrestricted execution. Attack: once module enabled, it can delegatecall arbitrary addresses with Safe's \
                                storage context, if module doesn't restrict target addresses/functions, malicious module operator can: execute arbitrary code as Safe, modify Safe's \
                                storage (ownership, threshold, module list), drain funds, brick contract. Example: module intended for automated payments, but allows delegatecall \
                                to any address, attacker calls selfdestruct, destroys Safe. Or: module delegatecalls to contract that does SSTORE to ownership slot, steals Safe. \
                                Missing: whitelist of allowed delegatecall targets, function selector validation, reentrancy guard. Should implement: only allow delegatecall to \
                                predetermined safe contracts, check function selectors against allowlist, use CALL instead of DELEGATECALL where possible.",
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

    fn detect_module_removal_bypass(&self) -> Vec<GnosisSafeModuleVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (module deactivation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_module_removal = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_module_removal {
                    let has_authorization_check = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let prevents_self_removal = window.iter().any(|&b| b == 0x33); // CALLER check
                    
                    if !prevents_self_removal {
                        vulns.push(GnosisSafeModuleVulnerability {
                            pc,
                            vulnerability_type: "ModuleRemovalBypass".to_string(),
                            description: format!(
                                "Module removal at PC {} can be bypassed by malicious module. Attack: if module can call disableModule on itself or manipulate module linked list, \
                                can prevent its own removal even after owners detect malicious behavior. Malicious module: (1) removes itself from module list in Safe's storage \
                                directly via delegatecall, (2) corrupts linked list pointers so disableModule fails, (3) front-runs removal transaction. Example: owners vote to \
                                disable compromised module, module sees pending transaction, uses delegatecall to corrupt module list, disableModule transaction fails or reverts. \
                                Attackers maintain access indefinitely. Missing: atomic module removal, prevent modules from modifying module list, emergency pause. Should implement: \
                                only allow Safe's execTransaction (not modules) to modify module list, use guardian mechanism for emergency module removal, implement module circuit \
                                breaker.",
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
