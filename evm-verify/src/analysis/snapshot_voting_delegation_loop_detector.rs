use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDelegationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SnapshotVotingDelegationLoopDetector {
    bytecode: Vec<u8>,
}

impl SnapshotVotingDelegationLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SnapshotDelegationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_circular_delegation());
        vulnerabilities.extend(self.detect_delegation_chain_depth_exploit());
        vulnerabilities.extend(self.detect_snapshot_block_manipulation());

        vulnerabilities
    }

    fn detect_circular_delegation(&self) -> Vec<SnapshotDelegationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (delegation storage)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_delegatee = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (delegate address)
                let has_delegator = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_delegatee && has_delegator {
                    let has_cycle_detection = window.iter().filter(|&&b| b == 0x54).count() >= 3; // Multiple SLOADs for chain traversal
                    let has_depth_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_cycle_detection && !has_depth_limit {
                        vulns.push(SnapshotDelegationVulnerability {
                            pc,
                            vulnerability_type: "CircularDelegation".to_string(),
                            description: format!(
                                "Delegation update at PC {} allows circular delegation chains (A→B→C→A). Circular loops \
                                cause infinite gas consumption when computing voting power or DoS voting system. Attack: \
                                create delegation cycle, cause vote tallying to revert, block proposal execution. Missing: \
                                cycle detection traversal, delegation chain depth limit, visited address tracking. \
                                Enables governance DoS via delegation loops.",
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

    fn detect_delegation_chain_depth_exploit(&self) -> Vec<SnapshotDelegationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (reading delegate)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_recursive_lookup = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOADs
                
                if has_recursive_lookup {
                    let has_depth_counter = window.iter().any(|&b| b == 0x01); // ADD (incrementing counter)
                    let has_max_depth = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_depth_counter || !has_max_depth {
                        vulns.push(SnapshotDelegationVulnerability {
                            pc,
                            vulnerability_type: "DelegationChainDepthExploit".to_string(),
                            description: format!(
                                "Delegation chain traversal at PC {} without depth limit. Attack: create delegation chain \
                                A→B→C→D→...→Z of unbounded length, cause gas exhaustion when computing voting power. \
                                Each delegation lookup consumes gas; long chains make vote counting prohibitively expensive. \
                                Missing: maximum delegation depth (e.g., 10 levels), depth counter, gas-efficient caching. \
                                Enables griefing attack preventing vote tallying.",
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

    fn detect_snapshot_block_manipulation(&self) -> Vec<SnapshotDelegationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER (snapshot block)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_storage_write = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_storage_write {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_minimum_delay = pre_window.iter().any(|&b| b == 0x03); // SUB (block number - delay)
                    let has_admin_check = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    
                    if has_admin_check && !has_minimum_delay {
                        vulns.push(SnapshotDelegationVulnerability {
                            pc,
                            vulnerability_type: "SnapshotBlockManipulation".to_string(),
                            description: format!(
                                "Snapshot block selection at PC {} controlled by admin without delay requirement. \
                                Attack: admin sets snapshot to past block after observing delegation state, choosing \
                                block favorable to desired outcome. Or sets snapshot to future block enabling flash-loan \
                                voting power acquisition. Missing: minimum snapshot delay (e.g., 1 hour), deterministic \
                                snapshot logic, community-controllable parameters. Enables snapshot timing manipulation \
                                to influence vote results.",
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
