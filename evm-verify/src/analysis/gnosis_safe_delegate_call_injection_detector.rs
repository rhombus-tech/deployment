use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnosisSafeDelegateCallVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GnosisSafeDelegateCallInjectionDetector {
    bytecode: Vec<u8>,
}

impl GnosisSafeDelegateCallInjectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GnosisSafeDelegateCallVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unvalidated_delegatecall_target());
        vulnerabilities.extend(self.detect_missing_function_selector_whitelist());
        vulnerabilities.extend(self.detect_storage_collision_risk());
        vulnerabilities
    }

    fn detect_unvalidated_delegatecall_target(&self) -> Vec<GnosisSafeDelegateCallVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL
                let start = if pc > 120 { pc - 120 } else { 0 };
                let target_from_input = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                if target_from_input {
                    let validates_target = self.bytecode[start..pc].iter().filter(|&&b| b == 0x14).count() >= 2;
                    if !validates_target {
                        vulns.push(GnosisSafeDelegateCallVulnerability {
                            pc, 
                            vulnerability_type: "UnvalidatedDelegatecallTarget".to_string(),
                            description: format!("Delegatecall at PC {} to user-supplied address without validation, enabling complete Safe takeover. Attack: Gnosis Safe multi-sig allows delegatecall to arbitrary address, attacker proposes transaction with malicious contract, contract executed in Safe's context, attacker's code controls Safe storage, changes owners/threshold. Real attack: Safe with 3-of-5 threshold, attacker convinces 3 owners to sign delegatecall to attacker's contract, malicious contract does SSTORE to owners slot, replaces all owners with attacker addresses, attacker now controls Safe. Example: execTransaction(to: attackerContract, operation: DELEGATECALL, data: ''), attackerContract executes: assembly {{ sstore(OWNERS_SLOT, attackerAddress) }}, all funds stolen. Missing: target whitelist, module authorization. Should implement: require(approvedModules[target]) before delegatecall. Fix: maintain whitelist of approved delegate targets, require governance approval to add targets, or restrict delegatecall to specific module addresses only.", pc),
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

    fn detect_missing_function_selector_whitelist(&self) -> Vec<GnosisSafeDelegateCallVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_calldata = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if has_calldata {
                    let validates_selector = self.bytecode[start..pc].iter().filter(|&&b| b == 0x00).count() >= 1;
                    if !validates_selector {
                        vulns.push(GnosisSafeDelegateCallVulnerability {
                            pc,
                            vulnerability_type: "MissingFunctionSelectorWhitelist".to_string(),
                            description: format!("Delegatecall at PC {} doesn't validate function selector, allowing dangerous function execution. Attack: even if delegatecall target is approved module, unrestricted function access enables calling admin functions, arbitrary storage writes, or self-destruct. Real attack: Safe allows delegatecall to approved DeFi module, module has upgradeAdmin() function, attacker includes this selector in calldata, becomes module admin, upgrades module to malicious implementation. Example: execTransaction(to: approvedModule, data: selfdestruct(attacker)), approved module contains selfdestruct, Safe destroyed. Missing: function selector whitelist, dangerous function blacklist. Should implement: bytes4 selector = bytes4(data); require(allowedSelectors[target][selector]). Fix: for each approved module, maintain list of safe function selectors, validate selector before delegatecall, blacklist dangerous functions like selfdestruct, upgradeAdmin, etc.", pc),
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

    fn detect_storage_collision_risk(&self) -> Vec<GnosisSafeDelegateCallVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window_end = (pc + 80).min(self.bytecode.len());
                let validates_no_storage_write = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x55).count() == 0;
                if !validates_no_storage_write {
                    vulns.push(GnosisSafeDelegateCallVulnerability {
                        pc,
                        vulnerability_type: "StorageCollisionRisk".to_string(),
                        description: format!("Delegatecall at PC {} risks storage collision between Safe and module, enabling corruption. Attack: delegatecall executes module code in Safe's storage context, if module's storage layout doesn't match Safe's, SSTORE operations overwrite critical Safe state like owners, threshold, nonce. Real vulnerability: Safe storage slot 0 = singleton address, Module storage slot 0 = admin address, delegatecall to module writes admin to slot 0, overwrites Safe singleton pointer, Safe broken. Example: module does admin = msg.sender (SSTORE 0), Safe's singleton pointer overwritten, future delegatecalls to msg.sender instead of intended implementation, Safe bricked or stolen. Missing: storage namespace isolation, append-only module storage. Should implement: modules use high storage slots (e.g., keccak256(id) + offset) avoiding collision. Fix: enforce storage layout convention where modules only write to slots >= 2^128, or use delegatecall only to view functions, or validate module doesn't modify storage during execution.", pc),
                        confidence: 0.82,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
