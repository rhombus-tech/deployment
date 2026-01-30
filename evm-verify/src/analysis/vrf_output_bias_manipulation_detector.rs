use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfOutputBiasVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VrfOutputBiasManipulationDetector {
    bytecode: Vec<u8>,
}

impl VrfOutputBiasManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VrfOutputBiasVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_output_modulo_bias());
        vulnerabilities.extend(self.detect_selective_vrf_reveal());
        vulnerabilities.extend(self.detect_insufficient_vrf_verification());
        vulnerabilities
    }

    fn detect_output_modulo_bias(&self) -> Vec<VrfOutputBiasVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x06 { // MOD (VRF output reduction)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let operates_on_vrf = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 2;
                if operates_on_vrf {
                    let has_bias_correction = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_bias_correction {
                        vulns.push(VrfOutputBiasVulnerability {
                            pc,
                            vulnerability_type: "OutputModuloBias".to_string(),
                            description: format!("VRF output reduction at PC {} uses modulo introducing statistical bias. Attack: VRF output uniformly distributed over 2^256, reducing mod N where N doesn't divide 2^256 creates bias toward lower values, attacker exploits bias to increase winning probability in lottery/randomness applications. Real vulnerability: randomNumber = vrfOutput % 100, if vrfOutput in [0, 2^256-1], values [0, 2^256 mod 100) appear more frequently than others, probability imbalance of ~0.05%. Example: lottery with 100 tickets, VRF % 100 gives ticket 0-55 probability 1/100 + epsilon, tickets 56-99 probability 1/100, attacker buys tickets 0-55 with 0.055% advantage. Missing: rejection sampling, bias elimination. Should implement: if(vrfOutput >= 2^256 - (2^256 % N)) retry, or use vrfOutput * N / 2^256. Fix: implement unbiased reduction via rejection sampling, or use full-domain multiplication: result = (vrfOutput * range) >> 256, eliminates modulo bias.", pc),
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

    fn detect_selective_vrf_reveal(&self) -> Vec<VrfOutputBiasVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (VRF result storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let stores_vrf = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 2;
                if stores_vrf {
                    let has_commit_reveal = self.bytecode[start..pc].iter().filter(|&&b| b == 0x42).count() >= 1;
                    let enforces_deadline = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !has_commit_reveal || !enforces_deadline {
                        vulns.push(VrfOutputBiasVulnerability {
                            pc,
                            vulnerability_type: "SelectiveVrfReveal".to_string(),
                            description: format!("VRF result storage at PC {} allows selective reveal, enabling bias manipulation. Attack: VRF requester can choose whether to reveal result, tries VRF repeatedly off-chain, only reveals when output favorable, biases randomness distribution. Real attack: lottery requester computes VRF locally, if winning number < 10 reveals, otherwise doesn't submit, effective probability becomes P(win | reveal) > P(win). Example: protocol uses block proposer's VRF for randomness, proposer computes VRF for next block, if unfavorable withholds block, tries again next slot, selectively reveals only favorable randomness. Missing: commit-reveal enforced, reveal deadline. Should implement: require commit before seeing outcome, enforce reveal within N blocks or slash. Fix: two-phase VRF: commit phase stores hash(vrfOutput), reveal phase proves VRF matches commitment, if no reveal within deadline punishment applied, prevents selective disclosure.", pc),
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

    fn detect_insufficient_vrf_verification(&self) -> Vec<VrfOutputBiasVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (VRF verification)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_proof = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 5;
                if has_proof {
                    let verifies_proof = self.bytecode[start..pc].iter().filter(|&&b| b == 0x14).count() >= 3;
                    if !verifies_proof {
                        vulns.push(VrfOutputBiasVulnerability {
                            pc,
                            vulnerability_type: "InsufficientVrfVerification".to_string(),
                            description: format!("VRF verification at PC {} doesn't fully validate proof, allowing forged randomness. Attack: VRF requires cryptographic proof that output derived from secret key and input, insufficient verification allows attacker to submit arbitrary values as VRF output, completely controlling randomness. Real vulnerability: contract accepts (output, proof) but only checks hash(output) without verifying proof validity, attacker submits (favorableOutput, randomProof), verification passes, randomness controlled. Example: VRF verification checks signature on output but not that output = H(sk, input), attacker signs chosen output, passes verification, randomness no longer unpredictable. Missing: full VRF proof verification (gamma, c, s components). Should implement: verify proof with VRF_Verify(pk, input, output, proof) checking all cryptographic components. Fix: use standardized VRF library (RFC 9381), verify: 1) proof.gamma = sk * H(input), 2) proof.c = H(pk || gamma || ...), 3) proof.s = k - c*sk, reject if any check fails.", pc),
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
