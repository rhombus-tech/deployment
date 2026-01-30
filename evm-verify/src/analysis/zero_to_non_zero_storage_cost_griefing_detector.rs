use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageCostGriefingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ZeroToNonZeroStorageCostGriefingDetector {
    bytecode: Vec<u8>,
}

impl ZeroToNonZeroStorageCostGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StorageCostGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unprotected_storage_expansion());
        vulnerabilities.extend(self.detect_array_push_gas_griefing());
        vulnerabilities.extend(self.detect_mapping_slot_initialization_dos());

        vulnerabilities
    }

    fn detect_unprotected_storage_expansion(&self) -> Vec<StorageCostGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_controlled_value = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_user_controlled_value {
                    let has_zero_check = window.iter().any(|&b| b == 0x15); // ISZERO
                    let has_gas_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_existing_value_check = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOAD
                    
                    if !has_zero_check || !has_existing_value_check {
                        vulns.push(StorageCostGriefingVulnerability {
                            pc,
                            vulnerability_type: "UnprotectedStorageExpansion".to_string(),
                            description: format!(
                                "Storage write at PC {} allows attacker-controlled zero-to-nonzero transitions. Attack: write many \
                                new storage slots (20,000 gas each vs 5,000 for updates), causing victim to pay excessive gas. \
                                EIP-2200/EIP-1087 makes first write to new slot 5x more expensive. Missing: check if slot already \
                                nonzero before write, gas limit per transaction, storage slot count cap. Should verify slot != 0 \
                                before allowing user-controlled writes.",
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

    fn detect_array_push_gas_griefing(&self) -> Vec<StorageCostGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (array length update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_add = window.iter().any(|&b| b == 0x01); // ADD (incrementing length)
                let has_array_access = window.iter().any(|&b| b == 0x20); // KECCAK256 (array slot calc)
                
                if has_add && has_array_access {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_second_sstore = forward.iter().any(|&b| b == 0x55); // Array element write
                    
                    if has_second_sstore {
                        let has_max_length_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                        let has_gas_check = window.iter().any(|&b| b == 0x5A); // GAS
                        
                        if !has_max_length_check {
                            vulns.push(StorageCostGriefingVulnerability {
                                pc,
                                vulnerability_type: "ArrayPushGasGriefing".to_string(),
                                description: format!(
                                    "Array push at PC {} without length limit. Attacker can append elements until array massive, \
                                    then operations iterating array (pop, iteration, deletion) cost millions of gas, DoS victim. \
                                    First push to new index costs 20k gas. Missing: maximum array length validation, gas-efficient \
                                    sparse array pattern, pagination for large arrays. Should cap array.length to prevent unbounded \
                                    growth and ensure O(1) operations.",
                                    pc
                                ),
                                confidence: 0.85,
                            });
                        }
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

    fn detect_mapping_slot_initialization_dos(&self) -> Vec<StorageCostGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (mapping slot calculation)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_sload = window.iter().any(|&b| b == 0x54); // SLOAD
                let has_sstore = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_sload && has_sstore {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_user_key = pre_window.iter().any(|&b| matches!(b, 0x35 | 0x33)); // CALLDATALOAD, CALLER
                    
                    if has_user_key {
                        let has_slot_count_limit = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                        let has_deposit_requirement = pre_window.iter().any(|&b| b == 0x34); // CALLVALUE
                        
                        if !has_slot_count_limit && !has_deposit_requirement {
                            vulns.push(StorageCostGriefingVulnerability {
                                pc,
                                vulnerability_type: "MappingSlotInitializationDoS".to_string(),
                                description: format!(
                                    "Mapping access at PC {} allows free slot initialization. Attacker creates thousands of unique \
                                    keys (mapping[attacker_address_1], mapping[attacker_address_2], ...), each costing 20k gas to \
                                    initialize. Victim clearing mapping or migrating to new contract pays massive gas. Missing: \
                                    slot creation fee/deposit, maximum slots per address, lazy deletion pattern. Should require \
                                    economic cost to prevent spam slot creation.",
                                    pc
                                ),
                                confidence: 0.83,
                            });
                        }
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
