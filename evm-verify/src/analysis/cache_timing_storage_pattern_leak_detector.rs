use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheTimingStoragePatternVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CacheTimingStoragePatternLeakDetector {
    bytecode: Vec<u8>,
}

impl CacheTimingStoragePatternLeakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CacheTimingStoragePatternVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_data_dependent_storage_access());
        vulnerabilities.extend(self.detect_secret_dependent_branching());
        vulnerabilities.extend(self.detect_variable_time_loop_iteration());
        vulnerabilities
    }

    fn detect_data_dependent_storage_access(&self) -> Vec<CacheTimingStoragePatternVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD
                let start = if pc > 100 { pc - 100 } else { 0 };
                let key_from_secret = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if key_from_secret {
                    let has_constant_time_access = self.bytecode[start..pc].iter().any(|&b| b == 0x15);
                    if !has_constant_time_access {
                        vulns.push(CacheTimingStoragePatternVulnerability {
                            pc,
                            vulnerability_type: "DataDependentStorageAccess".to_string(),
                            description: format!("Storage access at PC {} uses secret-dependent key, leaking information via cache timing. Attack: storage slot address derived from secret value, SLOAD timing varies based on cache state, attacker measures transaction gas usage, infers which storage slots accessed, deduces secret. Real attack: private key stored at slot keccak256(secretBit || baseSlot), accessing slot reveals secretBit via timing, 256 queries extract full key. Example: zk-SNARK verifier stores witness at hash(witness), verifier gas usage differs if slot cached vs uncached, attacker submits many proofs, measures gas, determines which witness values previously seen. Missing: constant-time storage access pattern, data-independent addressing. Should implement: access all candidate slots regardless of secret, or use ORAM-style oblivious storage. Fix: pre-load all potentially accessed slots, use dummy reads to ensure constant number of SLOADs, implement storage access pattern that's independent of secret data.", pc),
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

    fn detect_secret_dependent_branching(&self) -> Vec<CacheTimingStoragePatternVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI
                let start = if pc > 120 { pc - 120 } else { 0 };
                let condition_from_secret = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 1;
                if condition_from_secret {
                    let followed_by_different_ops = {
                        let window = (pc + 50).min(self.bytecode.len());
                        let opcodes: Vec<u8> = self.bytecode[pc..window].iter().copied().collect();
                        opcodes.iter().filter(|&&b| matches!(b, 0x54 | 0x55 | 0xF1)).count() >= 2
                    };
                    if followed_by_different_ops {
                        vulns.push(CacheTimingStoragePatternVulnerability {
                            pc,
                            vulnerability_type: "SecretDependentBranching".to_string(),
                            description: format!("Conditional branch at PC {} depends on secret data, creating timing side-channel. Attack: branch condition derived from secret, different execution paths have different timing/gas, attacker measures timing, infers which branch taken, extracts secret bits. Real vulnerability: if (privateKey[i] == 1) {{ complexOperation(); }}, timing reveals bit value, 256 measurements extract full key. Example: encryption function branches on key bits, one path does SLOAD (2100 gas), other does SSTORE (20000 gas), gas difference reveals key bit. Missing: constant-time execution, branchless implementation. Should implement: compute both branches and select result, or ensure identical gas cost. Fix: replace conditional with bitwise selection: result = (condition * path1) + ((1-condition) * path2), ensure both paths execute identical operations.", pc),
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

    fn detect_variable_time_loop_iteration(&self) -> Vec<CacheTimingStoragePatternVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI (loop)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_loop_structure = self.bytecode[start..pc].iter().filter(|&&b| b == 0x57).count() >= 2;
                if has_loop_structure {
                    let counter_from_secret = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if counter_from_secret {
                        vulns.push(CacheTimingStoragePatternVulnerability {
                            pc,
                            vulnerability_type: "VariableTimeLoopIteration".to_string(),
                            description: format!("Loop at PC {} has iteration count dependent on secret, leaking via timing. Attack: loop iterations determined by secret value, attacker measures total gas, divides by per-iteration cost, determines iteration count, extracts secret. Real attack: for(i=0; i<secretLength; i++) process(data[i]), gas = baseGas + secretLength*iterGas, attacker computes secretLength = (totalGas - baseGas) / iterGas. Example: RSA private key operation loops secretExponent times, timing reveals exponent bitlength, reduces keyspace by 2^(256-actualBits). Missing: constant iteration count, timing-independent loops. Should implement: always iterate maximum times, use conditional processing. Fix: for(i=0; i<MAX_ITERATIONS; i++) {{ if(i < secretLength) process(); else dummy(); }}, ensure dummy operations have identical cost.", pc),
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
