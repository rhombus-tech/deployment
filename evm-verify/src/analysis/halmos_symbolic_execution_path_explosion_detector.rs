use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HalmosSymbolicExecutionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HalmosSymbolicExecutionPathExplosionDetector {
    bytecode: Vec<u8>,
}

impl HalmosSymbolicExecutionPathExplosionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HalmosSymbolicExecutionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_branching_explosion());
        vulnerabilities.extend(self.detect_symbolic_storage_explosion());
        vulnerabilities.extend(self.detect_unconstrained_symbolic_input());
        vulnerabilities
    }

    fn detect_branching_explosion(&self) -> Vec<HalmosSymbolicExecutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI
                let start = if pc > 100 { pc - 100 } else { 0 };
                let branch_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x57).count();
                if branch_count >= 4 {
                    let constrains_paths = self.bytecode[start..pc].iter().filter(|&&b| b == 0x15).count() >= 2;
                    if !constrains_paths {
                        vulns.push(HalmosSymbolicExecutionVulnerability {
                            pc, vulnerability_type: "BranchingExplosion".to_string(),
                            description: format!("Multiple nested branches at PC {} cause Halmos path explosion, incomplete symbolic execution. Attack: function has many conditional branches on symbolic inputs, Halmos explores 2^N paths, memory/time exhausted, verification incomplete, vulnerabilities on unexplored paths missed. Real scenario: 10 nested if statements create 1024 execution paths, Halmos explores 100 paths in time limit, 924 paths unverified, bug on path 500 undetected. Example: if (a) if (b) if (c) if (d) ... each boolean symbolic, exponential path explosion, Halmos reports 'path exploration incomplete', false negative on assertion violation. Missing: symbolic input constraints, path merging, branch elimination. Should implement: vm.assume() to constrain symbolic values, reduce branching with lookup tables, merge equivalent paths. Fix: use Halmos --solver-timeout-assertion to fail fast, add vm.assume(a && b || !a && !b) to prune infeasible paths, refactor nested conditions to switch statements.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_symbolic_storage_explosion(&self) -> Vec<HalmosSymbolicExecutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_symbolic_key = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if has_symbolic_key {
                    let bounds_key_space = self.bytecode[start..pc].iter().any(|&b| b == 0x10);
                    if !bounds_key_space {
                        vulns.push(HalmosSymbolicExecutionVulnerability {
                            pc, vulnerability_type: "SymbolicStorageExplosion".to_string(),
                            description: format!("Symbolic storage write at PC {} with unbounded key causes Halmos memory explosion. Attack: storage writes with symbolic addresses create infinite storage models, Halmos must track all possible SSTORE locations, memory exhausted, verification crashes. Real vulnerability: mapping[userInput] = value, userInput symbolic, Halmos creates symbolic storage array, each path needs separate storage state, OOM. Example: balances[symbolicAddress] += amount, Halmos explores paths for all possible addresses (2^160), can't represent storage symbolically, verification fails or times out. Missing: symbolic address space bounds, concrete key constraints. Should implement: vm.assume(userInput < MAX_USERS), restrict symbolic keys to small domain, use concrete addresses in tests. Fix: Halmos --storage-layout to optimize symbolic storage, add symbolic array bounds with vm.assume(), refactor to use bounded arrays instead of mappings in test scenarios.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_unconstrained_symbolic_input(&self) -> Vec<HalmosSymbolicExecutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 80).min(self.bytecode.len());
                let used_in_computation = self.bytecode[pc..window_end].iter().filter(|&&b| matches!(b, 0x01 | 0x02 | 0x04)).count() >= 2;
                if used_in_computation {
                    let has_input_validation = self.bytecode[pc..window_end].iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                    if !has_input_validation {
                        vulns.push(HalmosSymbolicExecutionVulnerability {
                            pc, vulnerability_type: "UnconstrainedSymbolicInput".to_string(),
                            description: format!("Symbolic input at PC {} used without constraints, causing Halmos infeasible path exploration. Attack: Halmos treats all inputs as fully symbolic, explores paths impossible in practice, wastes computation on unrealistic scenarios, misses real bugs on feasible paths. Real scenario: function(uint256 amount) with amount symbolic over full uint256 range, Halmos explores amount = type(uint256).max causing overflows never occurring in practice, timeout on realistic amount ranges. Example: symbolic fuzz test with vm.assume() missing, Halmos explores amount=0, amount=1, amount=MAX, ratio of realistic to total paths tiny, real vulnerability at amount=1000 missed due to timeout. Missing: vm.assume() for input ranges, realistic symbolic bounds. Should implement: vm.assume(amount > 0 && amount < 1e24), constrain symbolic inputs to practical ranges, use Halmos --loop-bound to limit iterations. Fix: add preconditions via vm.assume(), bound symbolic arrays with vm.assume(arr.length <= 100), use concrete values for parameters not under test.", pc),
                            confidence: 0.79,
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
