use serde::{Deserialize, Serialize};

/// EIP-712 Domain Separator Phishing Detection
/// 
/// Detects EIP-712 signature phishing vulnerabilities:
/// 1. Domain separator missing chain ID
/// 2. Domain name too generic
/// 3. verifyingContract not validated
/// 4. Domain separator not cached properly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip712DomainPhishingVulnerability {
    /// Critical: Domain separator missing chain ID
    MissingChainId {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: Generic domain name
    GenericDomainName {
        description: String,
        location: usize,
        domain_name: String,
    },
    /// High: verifyingContract not checked
    VerifyingContractNotValidated {
        description: String,
        location: usize,
    },
    /// Medium: Domain separator not properly cached
    DomainSeparatorNotCached {
        description: String,
        location: usize,
    },
}

pub struct Eip712DomainPhishingDetector {
    bytecode: Vec<u8>,
}

impl Eip712DomainPhishingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip712DomainPhishingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Find DOMAIN_SEPARATOR construction
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.is_domain_separator_construction(i) {
                let has_chain_id = self.includes_chain_id(i, i + 200);
                
                if !has_chain_id {
                    vulnerabilities.push(Eip712DomainPhishingVulnerability::MissingChainId {
                        description: "EIP-712 domain separator does not include chainId".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
                
                // Check domain name
                if let Some(domain_name) = self.extract_domain_name(i, i + 200) {
                    if self.is_generic_domain_name(&domain_name) {
                        vulnerabilities.push(Eip712DomainPhishingVulnerability::GenericDomainName {
                            description: format!("Domain name '{}' is too generic", domain_name),
                            location: i,
                            domain_name,
                        });
                    }
                }
                
                // Check verifyingContract
                let validates_contract_address = self.validates_verifying_contract(i, i + 200);
                if !validates_contract_address {
                    vulnerabilities.push(Eip712DomainPhishingVulnerability::VerifyingContractNotValidated {
                        description: "verifyingContract field not validated against actual contract address".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 2: Check domain separator caching
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_domain_separator_getter(i) {
                let is_cached = self.domain_separator_is_cached(i, i + 150);
                
                if !is_cached {
                    vulnerabilities.push(Eip712DomainPhishingVulnerability::DomainSeparatorNotCached {
                        description: "Domain separator recalculated every time instead of cached".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_domain_separator_construction(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // EIP-712 domain separator construction uses keccak256 hash
        // with EIP712Domain typehash
        // EIP712Domain typehash: keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        
        self.bytecode[location..location + 50].windows(10).any(|w| {
            w.iter().any(|&b| b == 0x20) && // SHA3/KECCAK256
            w.iter().filter(|&&b| b == 0x60 || b == 0x61).count() >= 3 // Multiple PUSHes (fields)
        })
    }
    
    fn includes_chain_id(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for CHAINID opcode (0x46)
        self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x46) // CHAINID
    }
    
    fn extract_domain_name(&self, start: usize, end: usize) -> Option<String> {
        let range_end = end.min(self.bytecode.len());
        
        // Domain name is typically a string constant
        // Look for PUSH operations with string-like data
        
        for i in start..range_end {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f { // PUSH1-PUSH32
                let push_size = (self.bytecode[i] - 0x5f) as usize;
                if push_size > 4 && i + push_size < range_end {
                    let data = &self.bytecode[i + 1..i + 1 + push_size];
                    // Check if looks like ASCII text
                    if data.iter().all(|&b| b >= 0x20 && b <= 0x7e || b == 0) {
                        return Some(String::from_utf8_lossy(data).trim_end_matches('\0').to_string());
                    }
                }
            }
        }
        
        None
    }
    
    fn is_generic_domain_name(&self, name: &str) -> bool {
        // Generic names that could be phishing
        let generic_names = vec![
            "app", "dapp", "contract", "token", "protocol", 
            "defi", "exchange", "swap", "test", "demo"
        ];
        
        let name_lower = name.to_lowercase();
        generic_names.iter().any(|&generic| name_lower.contains(generic) && name_lower.len() < 15)
    }
    
    fn validates_verifying_contract(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Should use ADDRESS opcode (0x30) and compare with stored/expected value
        let has_address = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x30); // ADDRESS
        
        let has_comparison = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x14); // EQ
        
        has_address && has_comparison
    }
    
    fn is_domain_separator_getter(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // DOMAIN_SEPARATOR() selector: 0x3644e515
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x36 && w[2] == 0x44 && w[3] == 0xe5
        })
    }
    
    fn domain_separator_is_cached(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Cached domain separator pattern:
        // 1. Check cached value exists (SLOAD)
        // 2. If exists, return it
        // 3. Otherwise, calculate and cache (SSTORE)
        
        let has_sload = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x54); // SLOAD
        
        let has_conditional = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x57); // JUMPI (conditional branch)
        
        let has_sstore = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x55); // SSTORE
        
        // All three components needed for proper caching
        has_sload && has_conditional && has_sstore
    }
}
