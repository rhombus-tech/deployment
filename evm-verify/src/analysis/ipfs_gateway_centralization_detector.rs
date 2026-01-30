use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct IpfsGatewayCentralizationDetector {
    bytecode: Vec<u8>,
}

impl IpfsGatewayCentralizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<IpfsVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_gateway_dependency());
        vulnerabilities.extend(self.detect_missing_pinning_verification());
        vulnerabilities.extend(self.detect_content_availability_risk());

        vulnerabilities
    }

    fn detect_single_gateway_dependency(&self) -> Vec<IpfsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // External call to fetch metadata/content
            if opcode == 0xF1 || opcode == 0xFA {
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check for IPFS CID pattern (base58 encoding indicators)
                let has_cid = self.bytecode[start..pc].windows(4).any(|w| {
                    w[0] == 0x51 && w[1] == 0x6D // "Qm" prefix for IPFS CIDv0
                });
                
                if has_cid {
                    // Check for multiple gateway URLs (redundancy)
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let call_count = self.bytecode[start..window_end].iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
                    
                    // Check for error handling (REVERT on failure)
                    let has_error_handling = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0xFD);
                    
                    if call_count < 2 && !has_error_handling {
                        vulns.push(IpfsVulnerability {
                            pc,
                            vulnerability_type: "SingleGatewayDependency".to_string(),
                            description: format!(
                                "IPFS content fetch at PC {} relies on single gateway. Centralization risks: \
                                (1) Gateway censors CID, (2) Gateway goes offline, (3) DNS hijacking, \
                                (4) Geographic blocking. NFT metadata becomes inaccessible. Use multiple gateways \
                                with fallback: try gateway1, if fail try gateway2, etc.",
                                pc
                            ),
                            confidence: 0.75,
                        });
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_missing_pinning_verification(&self) -> Vec<IpfsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE storing IPFS hash
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check for IPFS CID being stored
                let has_cid = self.bytecode[start..pc].windows(4).any(|w| w[0] == 0x51 && w[1] == 0x6D);
                
                if has_cid {
                    // Check for pinning service verification call
                    let has_verification_call = self.bytecode[start..pc].iter().filter(|&&b| b == 0xF1 || b == 0xFA).count() >= 2;
                    
                    if !has_verification_call {
                        vulns.push(IpfsVulnerability {
                            pc,
                            vulnerability_type: "MissingPinningVerification".to_string(),
                            description: format!(
                                "IPFS CID stored at PC {} without pinning verification. Content availability risk: \
                                (1) Original uploader can unpin, (2) No nodes guarantee hosting, (3) Content disappears \
                                over time. For NFTs/critical data: verify content pinned on multiple services \
                                (Pinata, Infura, Filebase) before storing CID.",
                                pc
                            ),
                            confidence: 0.70,
                        });
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_content_availability_risk(&self) -> Vec<IpfsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // External call to fetch content
            if opcode == 0xF1 || opcode == 0xFA {
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window_end = (pc + 60).min(self.bytecode.len());
                
                // Check for IPFS CID
                let has_cid = self.bytecode[start..window_end].windows(4).any(|w| w[0] == 0x51 && w[1] == 0x6D);
                
                if has_cid {
                    // Check for content hash verification (hash returned data)
                    let has_hash_check = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x20); // KECCAK256
                    
                    // Check for content size validation
                    let has_size_check = self.bytecode[(pc + 1)..window_end].windows(3).any(|w| {
                        (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0x15 // LT/GT + ISZERO
                    });
                    
                    if !has_hash_check && !has_size_check {
                        vulns.push(IpfsVulnerability {
                            pc,
                            vulnerability_type: "ContentAvailabilityRisk".to_string(),
                            description: format!(
                                "IPFS content at PC {} fetched without integrity verification. Gateway can: \
                                (1) Return different content than CID, (2) Inject malicious data, (3) Return partial content. \
                                Verify: hash(fetchedContent) == expectedHash, validate size limits, check content format.",
                                pc
                            ),
                            confidence: 0.65,
                        });
                    }
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
