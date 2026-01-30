/// Transaction Replay Profit Detector
/// Detects vulnerabilities to cross-chain replay attacks for profit

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReplayVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct TransactionReplayProfitDetector {
    bytecode: Vec<u8>,
}

impl TransactionReplayProfitDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TransactionReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_no_chain_id_validation());
        vulnerabilities.extend(self.detect_replay_vulnerable_signature());
        vulnerabilities.extend(self.detect_cross_chain_nonce_reuse());
        vulnerabilities
    }

    fn detect_no_chain_id_validation(&self) -> Vec<TransactionReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_signature_verification(pc) {
                if !self.has_chain_id_in_hash(pc, 200) {
                    vulnerabilities.push(TransactionReplayVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Signature verification at PC {} doesn't include chain ID. \
                            Transactions can be replayed across chains for profit.",
                            pc
                        ),
                        exploit_scenario:
                            "Cross-Chain Replay Attack:\n\
                             1. User authorizes transfer on Ethereum: transfer(recipient, 100 USDC)\n\
                             2. Signature doesn't include chain ID\n\
                             3. Same contract deployed on Polygon with same address\n\
                             4. User has 100 USDC on Polygon too\n\
                             5. Attacker copies the Ethereum transaction\n\
                             6. Attacker replays it on Polygon\n\
                             7. Signature is valid (same contract, same function)\n\
                             8. User's Polygon USDC is transferred\n\
                             9. User loses funds on multiple chains from one signature\n\n\
                             This has caused $10M+ losses in real exploits!\n\n\
                             Fix (EIP-712 with chain ID):\n\
                             bytes32 constant DOMAIN_SEPARATOR = keccak256(abi.encode(\n\
                                 keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),\n\
                                 keccak256(bytes(name)),\n\
                                 keccak256(bytes(version)),\n\
                                 block.chainid,  // CRITICAL!\n\
                                 address(this)\n\
                             ));\n\
                             \n\
                             function executeWithSignature(\n\
                                 address to,\n\
                                 uint256 amount,\n\
                                 bytes memory signature\n\
                             ) public {\n\
                                 bytes32 structHash = keccak256(abi.encode(\n\
                                     TRANSFER_TYPEHASH,\n\
                                     to,\n\
                                     amount,\n\
                                     nonce++\n\
                                 ));\n\
                                 \n\
                                 bytes32 digest = keccak256(abi.encodePacked(\n\
                                     '\\x19\\x01',\n\
                                     DOMAIN_SEPARATOR,  // Includes chain ID!\n\
                                     structHash\n\
                                 ));\n\
                                 \n\
                                 address signer = ecrecover(digest, v, r, s);\n\
                                 require(signer == owner, 'Invalid signature');\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_replay_vulnerable_signature(&self) -> Vec<TransactionReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_ecrecover_call(pc) {
                if !self.has_nonce_check_nearby(pc, 150) && !self.has_deadline_check_nearby(pc, 150) {
                    vulnerabilities.push(TransactionReplayVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Signature recovery at PC {} has no nonce or deadline. \
                            Valid signatures can be replayed multiple times on same chain.",
                            pc
                        ),
                        exploit_scenario:
                            "Same-Chain Replay Attack:\n\
                             1. User signs: approve(spender, 1000 tokens)\n\
                             2. Signature has no nonce or expiry\n\
                             3. Spender uses approval, transfers 1000 tokens\n\
                             4. Spender replays the signature\n\
                             5. Contract verifies signature again (still valid!)\n\
                             6. Spender gets another 1000 token approval\n\
                             7. Spender drains user's entire balance\n\n\
                             Fix:\n\
                             mapping(address => uint256) public nonces;\n\
                             \n\
                             struct Permit {\n\
                                 address owner;\n\
                                 address spender;\n\
                                 uint256 value;\n\
                                 uint256 nonce;\n\
                                 uint256 deadline;\n\
                             }\n\
                             \n\
                             function permit(Permit memory p, bytes memory signature) public {\n\
                                 require(block.timestamp <= p.deadline, 'Expired');\n\
                                 require(p.nonce == nonces[p.owner]++, 'Invalid nonce');\n\
                                 \n\
                                 bytes32 digest = hashPermit(p);\n\
                                 address signer = ecrecover(digest, v, r, s);\n\
                                 require(signer == p.owner, 'Invalid signature');\n\
                                 \n\
                                 _approve(p.owner, p.spender, p.value);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_cross_chain_nonce_reuse(&self) -> Vec<TransactionReplayVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_nonce_usage(pc) {
                if !self.has_chain_specific_nonce(pc, 180) {
                    vulnerabilities.push(TransactionReplayVulnerability {
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: format!(
                            "Nonce usage at PC {} isn't chain-specific. \
                            Cross-chain deployments can have nonce collisions allowing replays.",
                            pc
                        ),
                        exploit_scenario:
                            "Cross-Chain Nonce Collision:\n\
                             1. Contract deployed on Ethereum and Arbitrum (same address)\n\
                             2. Global nonce mapping: nonces[user] = X\n\
                             3. User executes transaction on Ethereum: nonce = X\n\
                             4. Ethereum nonce increments: nonces[user] = X + 1\n\
                             5. Arbitrum still has: nonces[user] = X\n\
                             6. Attacker replays Ethereum transaction on Arbitrum\n\
                             7. Nonce check passes (Arbitrum nonce is still X)\n\
                             8. Transaction executes on Arbitrum\n\
                             9. User loses funds on second chain\n\n\
                             Fix:\n\
                             // Chain-specific nonce storage\n\
                             mapping(uint256 => mapping(address => uint256)) public chainNonces;\n\
                             \n\
                             function executeWithSignature(...) public {\n\
                                 uint256 chainId = block.chainid;\n\
                                 uint256 expectedNonce = chainNonces[chainId][user];\n\
                                 \n\
                                 require(nonce == expectedNonce, 'Invalid nonce');\n\
                                 chainNonces[chainId][user]++;\n\
                                 \n\
                                 // Execute transaction\n\
                             }\n\
                             \n\
                             // Or include chain ID in signature hash (better):\n\
                             bytes32 digest = keccak256(abi.encode(\n\
                                 block.chainid, // Prevents cross-chain replay\n\
                                 user,\n\
                                 nonce,\n\
                                 data\n\
                             ));".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_signature_verification(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        // Look for ecrecover precompile call or inline recovery
        for i in pc..(pc + 100).min(self.bytecode.len()) {
            // STATICCALL to address 1 (ecrecover precompile)
            if self.bytecode[i] == 0xfa { // STATICCALL
                return true;
            }
        }
        false
    }

    fn has_chain_id_in_hash(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        // Look for CHAINID opcode before signature verification
        for i in start..pc {
            if self.bytecode[i] == 0x46 { // CHAINID
                return true;
            }
        }
        false
    }

    fn is_ecrecover_call(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() { return false; }
        for i in pc..(pc + 50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xfa || self.bytecode[i] == 0xf1 { // STATICCALL or CALL
                return true;
            }
        }
        false
    }

    fn has_nonce_check_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        let mut has_sload = false;
        let mut has_eq_check = false;
        for i in start..end {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if has_sload && self.bytecode[i] == 0x14 { // EQ
                has_eq_check = true;
            }
            if has_eq_check && self.bytecode[i] == 0xfd { // REVERT
                return true;
            }
        }
        false
    }

    fn has_deadline_check_nearby(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in (i + 1)..(i + 20).min(end) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_nonce_usage(&self, pc: usize) -> bool {
        if pc + 60 >= self.bytecode.len() { return false; }
        let mut has_sload = false;
        let mut has_sstore = false;
        for i in pc..(pc + 60).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        has_sload && has_sstore
    }

    fn has_chain_specific_nonce(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        // Look for CHAINID used in storage key calculation
        let mut has_chainid = false;
        let mut has_keccak = false;
        for i in start..end {
            if self.bytecode[i] == 0x46 { has_chainid = true; }
            if has_chainid && self.bytecode[i] == 0x20 { // KECCAK256
                has_keccak = true;
            }
        }
        has_chainid && has_keccak
    }
}
