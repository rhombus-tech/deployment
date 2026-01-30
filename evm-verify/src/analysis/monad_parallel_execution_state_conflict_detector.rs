use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonadParallelExecutionStateConflictVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MonadParallelExecutionStateConflictDetector {
    bytecode: Vec<u8>,
}

impl MonadParallelExecutionStateConflictDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MonadParallelExecutionStateConflictVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_read_write_conflict());
        vulnerabilities.extend(self.detect_dependency_tracking_bypass());
        vulnerabilities.extend(self.detect_parallel_nonce_manipulation());
        vulnerabilities
    }

    fn detect_read_write_conflict(&self) -> Vec<MonadParallelExecutionStateConflictVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (state write)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let reads_before_write = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 1;
                if reads_before_write {
                    let has_conflict_detection = self.bytecode[start..pc].iter().filter(|&&b| b == 0x14).count() >= 2;
                    if !has_conflict_detection {
                        vulns.push(MonadParallelExecutionStateConflictVulnerability {
                            pc,
                            vulnerability_type: "ReadWriteConflict".to_string(),
                            description: format!("State write at PC {} lacks parallel execution conflict detection enabling inconsistent state. Attack: Monad executes transactions in parallel optimistically, transaction A reads slot X, transaction B writes slot X, both execute simultaneously, A uses stale value, state inconsistency. Real attack: two parallel transactions updating counter, tx1 reads count=100 and increments, tx2 reads count=100 and increments, both write count=101, one increment lost despite both succeeding. Example: parallel DEX swaps both read same liquidity pool state, calculate slippage independently, both execute trades, final pool state violates constant product formula, arbitrageur extracts value from broken invariant. Missing: read-set/write-set tracking, conflict abort mechanism, sequential fallback. Should implement: track storage dependencies, abort conflicting transactions. Fix: implement read-set versioning (SLOAD records version), validate on SSTORE no parallel writes occurred, abort transaction if read-set invalidated, re-execute sequentially on conflict, add conflict detection oracle for Monad runtime.", pc),
                            confidence: 0.88,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_dependency_tracking_bypass(&self) -> Vec<MonadParallelExecutionStateConflictVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (external interaction)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let reads_state = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if reads_state {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let declares_dependency = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                    if !declares_dependency {
                        vulns.push(MonadParallelExecutionStateConflictVulnerability {
                            pc,
                            vulnerability_type: "DependencyTrackingBypass".to_string(),
                            description: format!("External call at PC {} doesn't declare state dependencies enabling parallel execution race. Attack: contract reads state then makes external call that modifies same state, Monad parallel executor misses implicit dependency, executes conflicting transactions simultaneously. Real vulnerability: contract calls oracle for price, uses price in calculation, parallel transaction updates oracle price, both transactions execute with inconsistent oracle view, arbitrage opportunity. Example: tx1 calls getPrice() reads $100, calculates swap output, tx2 updates price to $110 via oracle, both execute in parallel, tx1 gets favorable price despite oracle update, protocol loses funds. Missing: implicit dependency declaration, cross-contract state tracking. Should implement: declare all external state dependencies upfront. Fix: implement dependency hints for external calls (mark which contracts/slots will be accessed), add static analysis for dependency extraction, require contracts declare read/write sets in function signatures, fallback to sequential execution for untrackable dependencies.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_parallel_nonce_manipulation(&self) -> Vec<MonadParallelExecutionStateConflictVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x33 { // CALLER (user identification)
                let window_end = (pc + 120).min(self.bytecode.len());
                let increments_nonce = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x01).count() >= 1;
                if increments_nonce {
                    let has_atomic_increment = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 1;
                    if !has_atomic_increment {
                        vulns.push(MonadParallelExecutionStateConflictVulnerability {
                            pc,
                            vulnerability_type: "ParallelNonceManipulation".to_string(),
                            description: format!("Nonce handling at PC {} lacks atomicity enabling parallel execution nonce conflicts. Attack: user submits multiple transactions with sequential nonces, Monad executes in parallel, nonce increments race, some transactions with duplicate nonces, replay attacks possible. Real attack: user has nonce=5, submits tx6, tx7, tx8 simultaneously, parallel execution processes all three reading nonce=5, all increment to 6, only one succeeds, others invalid but state partially modified. Example: account abstraction wallet executes userOps in parallel, nonce tracking broken, attacker replays userOp with valid signature but reused nonce, parallel execution allows both original and replay, double-spend. Missing: atomic nonce increment, serialization for nonce-dependent transactions. Should implement: serialize all transactions from same sender. Fix: enforce sequential execution for transactions sharing sender address, implement atomic nonce increment (load-increment-store as single op), add nonce reservation system (claim nonce before execution), validate nonce uniqueness in parallel batch, abort all transactions from sender if any nonce conflict detected.", pc),
                            confidence: 0.80,
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
