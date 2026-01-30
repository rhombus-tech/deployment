use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeiV2OptimisticParallelizationRollbackAbuseVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SeiV2OptimisticParallelizationRollbackAbuseDetector {
    bytecode: Vec<u8>,
}

impl SeiV2OptimisticParallelizationRollbackAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SeiV2OptimisticParallelizationRollbackAbuseVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_rollback_frontrunning());
        vulnerabilities.extend(self.detect_partial_state_exposure());
        vulnerabilities.extend(self.detect_rollback_gas_griefing());
        vulnerabilities
    }

    fn detect_rollback_frontrunning(&self) -> Vec<SeiV2OptimisticParallelizationRollbackAbuseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (state read)
                let window_end = (pc + 120).min(self.bytecode.len());
                let used_in_decision = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x57).count() >= 1;
                if used_in_decision {
                    let has_rollback_protection = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 2;
                    if !has_rollback_protection {
                        vulns.push(SeiV2OptimisticParallelizationRollbackAbuseVulnerability {
                            pc,
                            vulnerability_type: "RollbackFrontrunning".to_string(),
                            description: format!("State read at PC {} lacks rollback protection enabling optimistic execution frontrunning. Attack: Sei v2 executes transaction optimistically, attacker observes tentative state changes before rollback, submits frontrunning transaction based on leaked information, gains unfair advantage. Real attack: DEX swap executes optimistically, updates pool state, oracle observes optimistic price, validator detects conflict and rolls back original swap, attacker already submitted transaction based on leaked price, exploits temporary mispricing. Example: tx1 buys 1M tokens optimistically (price increases), mempool watchers see state change, tx2 frontrun buys tokens at lower price before rollback, tx1 rolls back, tx2 executes at original price, sold at temporarily inflated price observed during optimistic execution. Missing: state commitment before execution, rollback atomicity, observation resistance. Should implement: hide optimistic state until finalized. Fix: delay state visibility until transaction finalized (no rollback possible), implement commitment scheme for optimistic execution (reveal only on success), add random delays to rollback timing preventing timing attacks, penalize transactions that depend on recently-rolled-back state.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_partial_state_exposure(&self) -> Vec<SeiV2OptimisticParallelizationRollbackAbuseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (state write)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let multiple_writes = self.bytecode[start..pc].iter().filter(|&&b| b == 0x55).count() >= 2;
                if multiple_writes {
                    let has_atomic_rollback = self.bytecode[start..pc].iter().filter(|&&b| b == 0xFD).count() >= 1;
                    if !has_atomic_rollback {
                        vulns.push(SeiV2OptimisticParallelizationRollbackAbuseVulnerability {
                            pc,
                            vulnerability_type: "PartialStateExposure".to_string(),
                            description: format!("Multiple state writes at PC {} lack atomic rollback enabling partial state leakage. Attack: transaction makes multiple state changes optimistically, partial rollback occurs (some writes persist, others revert), creates inconsistent intermediate state observable by other transactions. Real vulnerability: Sei v2 rolls back transaction but some storage slots already propagated to dependent transactions, partial state visible during rollback window, breaks atomicity assumptions. Example: swap transaction writes: (1) update reserves, (2) update user balance, (3) emit event, rollback occurs after step 2, reserves rolled back but balance change visible, subsequent transaction sees inconsistent balances without reserve update, arbitrage. Missing: transactional memory semantics, all-or-nothing rollback, snapshot isolation. Should implement: atomic multi-write rollback with snapshot isolation. Fix: implement copy-on-write for optimistic execution (all writes to shadow state), commit shadow state atomically only if no rollback, ensure dependent transactions see consistent snapshots (all changes or none), add version numbers to prevent reading partially-rolled-back state.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_rollback_gas_griefing(&self) -> Vec<SeiV2OptimisticParallelizationRollbackAbuseVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (expensive operation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let expensive_computation = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x02 | 0x05 | 0x20)).count() >= 5;
                if expensive_computation {
                    let has_rollback_compensation = self.bytecode[start..pc].iter().filter(|&&b| b == 0x34).count() >= 1;
                    if !has_rollback_compensation {
                        vulns.push(SeiV2OptimisticParallelizationRollbackAbuseVulnerability {
                            pc,
                            vulnerability_type: "RollbackGasGriefing".to_string(),
                            description: format!("Expensive operation at PC {} lacks rollback gas compensation enabling griefing attacks. Attack: attacker submits transaction designed to force rollback after expensive computation, Sei v2 executes optimistically consuming gas, rollback occurs, attacker's gas refunded but victim's gas wasted on rollback. Real attack: attacker crafts transaction conflicting with victim's tx, both execute optimistically with expensive computations, attacker's tx intentionally designed to trigger rollback condition, victim's computation wasted, attacker gas refunded. Example: victim deploys complex contract (1M gas optimistic execution), attacker submits conflicting transaction creating deployment address collision, both execute optimistically, collision detected during finalization, rollback occurs, victim loses gas for wasted computation. Missing: gas compensation for rollback victims, rollback gas accounting. Should implement: charge rollback instigators for wasted gas. Fix: track gas consumed during optimistic execution, on rollback charge rollback-causing transaction for all wasted gas from rolled-back transactions, refund victims from attacker's gas payment, implement rollback fee preventing spam (attacker pays premium for causing rollback), add reputation system penalizing frequent rollback causers.", pc),
                            confidence: 0.78,
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
