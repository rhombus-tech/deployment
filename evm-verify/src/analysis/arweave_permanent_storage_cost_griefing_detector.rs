use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArweavePermanentStorageVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ArweavePermanentStorageCostGriefingDetector {
    bytecode: Vec<u8>,
}

impl ArweavePermanentStorageCostGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ArweavePermanentStorageVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unbounded_storage_commitment());
        vulnerabilities.extend(self.detect_missing_storage_cost_validation());
        vulnerabilities.extend(self.detect_permanent_griefing_data());
        vulnerabilities
    }

    fn detect_unbounded_storage_commitment(&self) -> Vec<ArweavePermanentStorageVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (to Arweave bridge)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_data_size = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if has_data_size {
                    let validates_size = self.bytecode[start..pc].iter().any(|&b| b == 0x10);
                    if !validates_size {
                        vulns.push(ArweavePermanentStorageVulnerability {
                            pc,
                            vulnerability_type: "UnboundedStorageCommitment".to_string(),
                            description: format!("Arweave storage call at PC {} doesn't limit data size, enabling permanent storage griefing. Attack: contract commits to store user data permanently on Arweave without size limit, attacker submits gigabytes, protocol pays permanent storage costs, treasury drained. Real attack: NFT minting allows arbitrary metadata size, attacker mints NFT with 1GB metadata, protocol pays Arweave endowment for permanent 1GB storage, costs $1000+, repeated attacks bankrupt protocol. Example: decentralized social app stores posts on Arweave, user submits 100MB post, protocol pays permanent storage, attacker creates 1000 accounts posting max size, protocol owes $100K permanent storage. Missing: data size limits, cost caps. Should implement: require(data.length <= MAX_SIZE), calculate expected cost, validate budget. Fix: enforce maximum data size (e.g., 100KB per transaction), calculate Arweave endowment cost upfront, require user pays or limit free tier.", pc),
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

    fn detect_missing_storage_cost_validation(&self) -> Vec<ArweavePermanentStorageVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x02 { // MUL (cost calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let calculates_storage_cost = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if calculates_storage_cost {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let validates_payment = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !validates_payment {
                        vulns.push(ArweavePermanentStorageVulnerability {
                            pc,
                            vulnerability_type: "MissingStorageCostValidation".to_string(),
                            description: format!("Storage cost calculation at PC {} doesn't validate payment sufficiency, allowing underpayment. Attack: contract calculates Arweave storage cost but doesn't verify user paid enough, users store data permanently at protocol expense, treasury depleted. Real vulnerability: storeOnArweave(data) calculates cost = data.length * AR_PRICE_PER_BYTE, doesn't require msg.value >= cost, users call with msg.value = 0, protocol subsidizes permanent storage. Example: user stores 10MB for free, protocol pays 0.01 AR ($1), 1000 users drain $1000 from treasury. Missing: payment validation, refund excess. Should implement: uint cost = calculateStorageCost(data); require(msg.value >= cost). Fix: calculate exact storage cost, validate payment, refund excess, or use pull pattern where users pre-fund storage account.", pc),
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

    fn detect_permanent_griefing_data(&self) -> Vec<ArweavePermanentStorageVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (txid storage)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let stores_arweave_tx = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if stores_arweave_tx {
                    let has_moderation = self.bytecode[start..pc].iter().any(|&b| b == 0x14);
                    if !has_moderation {
                        vulns.push(ArweavePermanentStorageVulnerability {
                            pc,
                            vulnerability_type: "PermanentGriefingData".to_string(),
                            description: format!("Arweave transaction storage at PC {} allows permanent storage of griefing data without moderation. Attack: contract stores any user data permanently on Arweave, attacker uploads illegal/malicious content, protocol legally liable, content permanently associated with protocol. Real attack: decentralized app stores user content on Arweave with protocol address as upload source, attacker uploads illegal content, protocol implicated, unable to remove due to Arweave permanence. Example: NFT platform allows arbitrary image uploads to Arweave, attacker uploads copyrighted/illegal images, platform faces legal action, cannot delete permanent data. Missing: content moderation, allowlist, pre-upload validation. Should implement: content hash whitelist, IPFS CID validation, or centralized review before Arweave commit. Fix: implement two-phase storage: temporary IPFS storage first, content reviewed, only approved content committed to permanent Arweave, or require users upload directly to Arweave with their own wallet, contract only stores transaction ID.", pc),
                            confidence: 0.77,
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
