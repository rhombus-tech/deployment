use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip4844BlobStorageCostVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Eip4844BlobStorageCostManipulationDetector {
    bytecode: Vec<u8>,
}

impl Eip4844BlobStorageCostManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Eip4844BlobStorageCostVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_blob_gas_price_manipulation());
        vulnerabilities.extend(self.detect_missing_blob_verification());
        vulnerabilities.extend(self.detect_blob_data_availability_assumption());
        vulnerabilities
    }

    fn detect_blob_gas_price_manipulation(&self) -> Vec<Eip4844BlobStorageCostVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x49 { // BLOBBASEFEE (EIP-4844 opcode)
                let window_end = (pc + 100).min(self.bytecode.len());
                let used_in_pricing = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x02).count() >= 1;
                if used_in_pricing {
                    let has_bounds_check = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_bounds_check {
                        vulns.push(Eip4844BlobStorageCostVulnerability {
                            pc,
                            vulnerability_type: "BlobGasPriceManipulation".to_string(),
                            description: format!("Blob gas price usage at PC {} doesn't validate bounds, enabling cost manipulation. Attack: contract uses BLOBBASEFEE for pricing without bounds, during blob gas price spike users pay excessive fees, or during low prices protocol subsidizes storage costs. Real vulnerability: L2 batch submission uses BLOBBASEFEE * blobCount for fee calculation, blob price spikes 100x, users charged 100x expected, transactions fail or overpay. Example: zkRollup posts batches when BLOBBASEFEE < threshold, attacker floods network increasing blob demand, BLOBBASEFEE exceeds threshold, batch posting paused, L2 transactions delayed creating DoS. Missing: BLOBBASEFEE bounds validation, fallback pricing. Should implement: require(blobBaseFee <= MAX_BLOB_FEE), use time-weighted average pricing. Fix: cap maximum blob gas price accepted, implement TWAP for blob pricing, add fallback to calldata if blob price exceeds threshold.", pc),
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

    fn detect_missing_blob_verification(&self) -> Vec<Eip4844BlobStorageCostVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x4A { // BLOBHASH (EIP-4844 opcode)
                let window_end = (pc + 100).min(self.bytecode.len());
                let stores_hash = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if stores_hash {
                    let verifies_hash = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 1;
                    if !verifies_hash {
                        vulns.push(Eip4844BlobStorageCostVulnerability {
                            pc,
                            vulnerability_type: "MissingBlobVerification".to_string(),
                            description: format!("Blob hash storage at PC {} doesn't verify blob commitment, enabling data substitution. Attack: contract stores BLOBHASH without verification, attacker submits transaction with blob commitment, replaces blob data before verification, invalid data committed. Real attack: L2 sequencer posts batch commitment via BLOBHASH, stores hash without verifying KZG proof, attacker provides invalid blob with matching hash but corrupt data, L2 state corrupted. Example: rollup stores blobHash = BLOBHASH(0), later retrieves blob data, data doesn't match expected state transition, fraud proof verification impossible. Missing: KZG commitment verification, blob data validation. Should implement: verify point evaluation proof for blob commitment. Fix: call POINT_EVALUATION_PRECOMPILE (0x0A) to verify KZG proof, ensure blob data matches commitment before storage.", pc),
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

    fn detect_blob_data_availability_assumption(&self) -> Vec<Eip4844BlobStorageCostVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x4A { // BLOBHASH
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window_end = (pc + 120).min(self.bytecode.len());
                let assumes_availability = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                if assumes_availability {
                    let has_fallback = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x57).count() >= 1;
                    if !has_fallback {
                        vulns.push(Eip4844BlobStorageCostVulnerability {
                            pc,
                            vulnerability_type: "BlobDataAvailabilityAssumption".to_string(),
                            description: format!("Blob usage at PC {} assumes permanent availability without fallback, risking data loss. Attack: contract assumes blob data available forever, blobs pruned after 18 days, critical data lost, protocol state unrecoverable. Real vulnerability: L2 stores only blob hashes assuming blob retrievable, after 18 days blobs pruned, state transition proofs require blob data, fraud proofs impossible. Example: optimistic rollup posts state root with blob reference, 30 days later challenger needs blob to generate fraud proof, blob unavailable, invalid state finalized. Missing: blob data archival, calldata fallback, reconstruction mechanism. Should implement: store critical data in calldata or permanent storage. Fix: hybrid approach - recent data in blobs, critical data in calldata, archive blob data off-chain with availability proofs, implement data reconstruction from calldata if blobs unavailable.", pc),
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
