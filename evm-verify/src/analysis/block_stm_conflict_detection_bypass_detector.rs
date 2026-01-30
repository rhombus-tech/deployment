use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockStmConflictDetectionBypassVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BlockStmConflictDetectionBypassDetector {
    bytecode: Vec<u8>,
}

impl BlockStmConflictDetectionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BlockStmConflictDetectionBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_storage_aliasing());
        vulnerabilities.extend(self.detect_computed_slot_manipulation());
        vulnerabilities.extend(self.detect_cross_contract_dependency_hiding());
        vulnerabilities.extend(self.detect_dynamic_access_pattern());
        vulnerabilities
    }

    fn detect_storage_aliasing(&self) -> Vec<BlockStmConflictDetectionBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (keccak for slot calculation)
                let window_end = (pc + 100).min(self.bytecode.len());
                let used_for_storage = self.bytecode[pc..window_end].iter().any(|&b| b == 0x54 || b == 0x55);
                if used_for_storage {
                    let has_conflict_annotation = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 3;
                    if !has_conflict_annotation {
                        vulns.push(BlockStmConflictDetectionBypassVulnerability {
                            pc,
                            vulnerability_type: "StorageAliasing".to_string(),
                            description: format!("Computed storage slot at PC {} bypasses Block-STM conflict detection via aliasing. Attack: contract computes storage slot dynamically using keccak256, Block-STM static analysis can't predict slot access, parallel transactions conflict undetected, state inconsistency. Real attack: two transactions access same slot via different computation paths (keccak256(A,B) == keccak256(C,D) due to hash collision or intentional construction), Block-STM sees different access patterns, executes in parallel, final state incorrect. Example: ERC20 mapping balance[user] accessed via keccak256(user, 0) and indirectly via keccak256(proxy, sub_slot), both resolve to same storage slot, parallel transfers corrupt balance. Missing: storage alias detection, symbolic execution for slot resolution. Should implement: declare all possible storage accesses upfront. Fix: require contracts annotate aliased storage slots, implement runtime alias detection (track actual slot writes), add symbolic execution pass to resolve computed slots before parallel execution, fallback to sequential for unresolvable patterns, require storage access patterns in function metadata.", pc),
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

    fn detect_computed_slot_manipulation(&self) -> Vec<BlockStmConflictDetectionBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE
                let start = if pc > 120 { pc - 120 } else { 0 };
                let slot_computed = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x01 | 0x02 | 0x20)).count() >= 2;
                if slot_computed {
                    let has_dependency_declaration = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !has_dependency_declaration {
                        vulns.push(BlockStmConflictDetectionBypassVulnerability {
                            pc,
                            vulnerability_type: "ComputedSlotManipulation".to_string(),
                            description: format!("Computed slot write at PC {} bypasses Block-STM static dependency tracking. Attack: storage slot calculated from transaction input, attacker crafts inputs making different transactions appear independent to Block-STM, actually access same slot causing conflict. Real vulnerability: Block-STM analyzes bytecode statically to build dependency graph, computed slots (slot = keccak256(input_data)) unresolvable at analysis time, conservative approach serializes all, attacker exploits by making slots appear different. Example: vault contract stores user balances at slot = keccak256(user_address, nonce), two transactions with different nonces look independent, both map to same underlying balance due to nonce collision (intentional or protocol bug), parallel execution allows double-spend. Missing: dynamic dependency tracking, runtime conflict detection. Should implement: track actual storage accesses during execution. Fix: implement runtime dependency tracking (record actual slots accessed not predicted), add conflict detection on commit (check if parallel transactions touched overlapping slots), abort and re-execute conflicts sequentially, require deterministic slot computation for parallel execution, whitelist safe slot computation patterns (simple mappings only).", pc),
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

    fn detect_cross_contract_dependency_hiding(&self) -> Vec<BlockStmConflictDetectionBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (cross-contract)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let reads_state = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if reads_state {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let writes_state = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                    if writes_state {
                        let declares_cross_contract_dependency = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 3;
                        if !declares_cross_contract_dependency {
                            vulns.push(BlockStmConflictDetectionBypassVulnerability {
                                pc,
                                vulnerability_type: "CrossContractDependencyHiding".to_string(),
                                description: format!("Cross-contract call at PC {} hides dependencies from Block-STM inter-contract analysis. Attack: transaction reads state, calls external contract which modifies same state, Block-STM misses dependency chain, allows parallel execution with conflicting transaction. Real attack: Block-STM tracks intra-contract dependencies well but struggles with cross-contract, tx1 reads counter in contract A, calls contract B which writes counter in A, tx2 directly writes counter in A, Block-STM sees tx1 as read-only on A (call to B is opaque), executes both in parallel, counter corruption. Example: DeFi protocol reads oracle price (contract A), updates pool reserves based on price (contract B), another transaction updates oracle price, both execute in parallel, pool uses stale price, arbitrage opportunity. Missing: cross-contract dependency graph, call trace analysis. Should implement: track all storage accessed by entire call stack. Fix: implement full call graph analysis (track all contracts touched in transaction tree), mark transactions as conflicting if any contract in their call graphs overlap with state modifications, use optimistic execution with verification (track all actual accesses, abort if conflicts detected post-execution), require contracts declare external dependencies in metadata.", pc),
                                confidence: 0.80,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_dynamic_access_pattern(&self) -> Vec<BlockStmConflictDetectionBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI (conditional branching)
                let window_end = (pc + 150).min(self.bytecode.len());
                let branches_have_different_storage = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 2;
                if branches_have_different_storage {
                    let has_static_analysis_hint = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x20).count() >= 2;
                    if !has_static_analysis_hint {
                        vulns.push(BlockStmConflictDetectionBypassVulnerability {
                            pc,
                            vulnerability_type: "DynamicAccessPattern".to_string(),
                            description: format!("Conditional branching at PC {} creates dynamic storage access patterns defeating Block-STM static analysis. Attack: transaction storage access depends on runtime conditions, Block-STM cannot predict which branch taken, conservatively assumes all possible accesses, degrades parallelism, or misses conflicts if optimistic. Real vulnerability: Block-STM must predict read/write sets before execution, conditional code paths create uncertainty, if branch A writes slot X, branch B writes slot Y, Block-STM either assumes both (false dependencies) or picks wrong path (conflicts). Example: function processOrder(bool isMarketOrder) branches on order type, market orders write slot A (price), limit orders write slot B (queue), Block-STM cannot predict order type from static analysis, either serializes all orders or risks conflicts. Missing: execution prediction, branch probability analysis. Should implement: profile-guided optimization, record common paths. Fix: implement path profiling (track which branches taken in practice), use historical data to predict likely access patterns, add runtime verification (confirm predicted paths match actual), provide hints in code (likely/unlikely annotations for branches), require deterministic access patterns for parallel-eligible functions.", pc),
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
