use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryCreate2AddressPredictionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FactoryCreate2AddressPredictionRaceDetector {
    bytecode: Vec<u8>,
}

impl FactoryCreate2AddressPredictionRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FactoryCreate2AddressPredictionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unprotected_create2_frontrun());
        vulnerabilities.extend(self.detect_salt_prediction_race());
        vulnerabilities.extend(self.detect_initialization_frontrun());
        vulnerabilities
    }

    fn detect_unprotected_create2_frontrun(&self) -> Vec<FactoryCreate2AddressPredictionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF5 { // CREATE2
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_salt = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if has_salt {
                    let has_access_control = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                    if !has_access_control {
                        vulns.push(FactoryCreate2AddressPredictionVulnerability {
                            pc, vulnerability_type: "UnprotectedCreate2Frontrun".to_string(),
                            description: format!("CREATE2 deployment at PC {} lacks access control, allowing frontrun of predicted addresses. Attack: user calculates CREATE2 address off-chain, submits deployment transaction, attacker sees pending tx, frontruns with same salt, deploys malicious contract at predicted address, user's funds sent to attacker's contract. Real attack: user predicts address 0x1234 for token contract, prepares to send 100 ETH to 0x1234, attacker frontuns CREATE2 with identical salt, deploys fake token at 0x1234, user sends 100 ETH to attacker's contract. Example: Uniswap V3 pool factory uses CREATE2 for deterministic addresses, attacker monitors mempool, sees createPool(tokenA, tokenB, fee), frontruns with same parameters, deploys malicious pool at predicted address, liquidity providers deposit to fake pool. Missing: access control, commit-reveal scheme, nonce randomization. Should implement: require(msg.sender == owner), or use private salt. Fix: add onlyOwner modifier to CREATE2 functions, use commit-reveal pattern where salt revealed after commitment, include msg.sender in salt calculation.", pc),
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

    fn detect_salt_prediction_race(&self) -> Vec<FactoryCreate2AddressPredictionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (salt calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_predictable_input = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x35 | 0x43 | 0x42)).count() >= 2;
                if uses_predictable_input {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let followed_by_create2 = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF5);
                    if followed_by_create2 {
                        vulns.push(FactoryCreate2AddressPredictionVulnerability {
                            pc, vulnerability_type: "SaltPredictionRace".to_string(),
                            description: format!("Salt calculation at PC {} uses predictable inputs, enabling address prediction race. Attack: salt derived from block.timestamp or msg.sender, attacker predicts future salt values, pre-deploys contracts at future addresses, user transactions fail or interact with attacker's contracts. Real vulnerability: salt = keccak256(msg.sender, block.number), attacker knows their address and current block number, computes salt for next 100 blocks, deploys at all predicted addresses. Example: factory uses salt = keccak256(tokenName), attacker sees pending createToken('USDC'), computes address, deploys fake USDC at that address first, real deployment reverts with 'ContractAlreadyExists'. Missing: unpredictable entropy, commit-reveal, nonce inclusion. Should implement: salt = keccak256(msg.sender, nonce, blockhash(block.number - 1), randomSeed). Fix: include unpredictable component in salt (e.g., VRF output, future blockhash unavailable at prediction time), use commit-reveal where salt committed before reveal.", pc),
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

    fn detect_initialization_frontrun(&self) -> Vec<FactoryCreate2AddressPredictionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF5 { // CREATE2
                let window_end = (pc + 150).min(self.bytecode.len());
                let has_initialization_call = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                if has_initialization_call {
                    let has_atomicity = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0xFD).count() >= 1;
                    if !has_atomicity {
                        vulns.push(FactoryCreate2AddressPredictionVulnerability {
                            pc, vulnerability_type: "InitializationFrontrun".to_string(),
                            description: format!("CREATE2 deployment at PC {} separates creation from initialization, allowing frontrun initialization. Attack: factory deploys contract via CREATE2, initialization called separately, attacker frontruns initialization call, initializes contract with malicious parameters, legitimate initialization reverts, contract owned by attacker. Real attack: factory calls CREATE2 creating proxy at address 0xABCD, separate tx calls initialize(owner), attacker sees pending initialize(), frontruns with initialize(attackerAddress), attacker now owns contract at 0xABCD. Example: minimal proxy factory creates clone, owner plans to call initialize(legitimateOwner), attacker frontruns with initialize(attackerAddress), attacker gains control, user's funds sent to proxy now controlled by attacker. Missing: atomic deployment + initialization, initializer access control. Should implement: constructor initialization or single-tx deployment + init. Fix: use constructorless initialization check (require(!initialized)), or make factory call initialize() in same transaction as CREATE2, or use CREATE2 with constructor parameters for atomic initialization.", pc),
                            confidence: 0.84,
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
