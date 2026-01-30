use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsMetadataImmutabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct IpfsMetadataImmutabilityBypassDetector {
    bytecode: Vec<u8>,
}

impl IpfsMetadataImmutabilityBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<IpfsMetadataImmutabilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_mutable_ipfs_hash());
        vulnerabilities.extend(self.detect_centralized_gateway_dependency());
        vulnerabilities.extend(self.detect_missing_content_hash_validation());
        vulnerabilities
    }

    fn detect_mutable_ipfs_hash(&self) -> Vec<IpfsMetadataImmutabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (metadata storage)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let stores_ipfs_hash = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if stores_ipfs_hash {
                    let has_immutability_check = self.bytecode[start..pc].iter().filter(|&&b| b == 0x15).count() >= 1;
                    if !has_immutability_check {
                        vulns.push(IpfsMetadataImmutabilityVulnerability {
                            pc,
                            vulnerability_type: "MutableIpfsHash".to_string(),
                            description: format!("IPFS hash storage at PC {} allows updates, breaking metadata immutability guarantee. Attack: NFT/token promises immutable metadata via IPFS, contract allows owner to change IPFS hash, metadata switched post-sale, buyers deceived about asset properties. Real attack: NFT sold with art at ipfs://Qm123 (high-value artwork), after sale owner calls setTokenURI() changing to ipfs://Qm456 (worthless image), buyers hold NFT with different metadata than purchased. Example: gaming NFT metadata defines character stats, owner updates IPFS hash changing stats from legendary to common, player value destroyed. Missing: one-time-set enforcement, immutability lock. Should implement: require(tokenURISet[tokenId] == false) before setting, or remove setTokenURI entirely. Fix: make IPFS hash immutable after initial set, or require governance vote for metadata updates, emit events for any changes allowing buyers to verify.", pc),
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

    fn detect_centralized_gateway_dependency(&self) -> Vec<IpfsMetadataImmutabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x60 && pc + 20 < self.bytecode.len() {
                let potential_url = &self.bytecode[pc..pc+20];
                let looks_like_gateway = potential_url.iter().filter(|&&b| b == 0x2E).count() >= 2;
                if looks_like_gateway {
                    vulns.push(IpfsMetadataImmutabilityVulnerability {
                        pc,
                        vulnerability_type: "CentralizedGatewayDependency".to_string(),
                        description: format!("Metadata URL at PC {} uses centralized IPFS gateway, creating availability risk. Attack: contract returns metadata as https://gateway.ipfs.io/ipfs/Qm123, gateway provider goes down or censors content, all metadata inaccessible, NFTs appear blank/broken. Real vulnerability: NFT tokenURI returns 'https://infura.io/ipfs/' + hash, Infura experiences outage, all NFT images disappear from marketplaces, collection appears worthless. Example: 10,000 NFT collection uses single gateway, gateway company shuts down, metadata unretrievable, buyers cannot verify ownership or display assets. Missing: use ipfs:// protocol, decentralized access. Should implement: return 'ipfs://' + hash, let clients choose gateway. Fix: use ipfs:// URI scheme instead of HTTP gateway URLs, marketplaces/wallets resolve via their preferred gateway, removes single point of failure.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_content_hash_validation(&self) -> Vec<IpfsMetadataImmutabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD (metadata input)
                let window_end = (pc + 100).min(self.bytecode.len());
                let stores_metadata = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if stores_metadata {
                    let validates_hash_format = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x1A).count() >= 2;
                    if !validates_hash_format {
                        vulns.push(IpfsMetadataImmutabilityVulnerability {
                            pc,
                            vulnerability_type: "MissingContentHashValidation".to_string(),
                            description: format!("Metadata input at PC {} doesn't validate IPFS CID format, allowing invalid hashes. Attack: contract accepts arbitrary string as IPFS hash without validation, owner sets non-existent hash, metadata permanently unavailable, tokens broken. Real vulnerability: setTokenURI accepts any bytes32, owner sets 0x00 or random data, tokenURI returns invalid IPFS hash, metadata fetch fails. Example: owner mistakes, sets hash as hex string instead of IPFS CID, metadata unretrievable, NFT collection value destroyed. Missing: CID format validation, existence check. Should implement: validate hash starts with 'Qm' for CIDv0 or multibase for CIDv1. Fix: require CID validation: bytes memory cid = bytes(_ipfsHash); require(cid.length == 46 && cid[0] == 'Q' && cid[1] == 'm'), or use multihash library for proper CID parsing.", pc),
                            confidence: 0.76,
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
