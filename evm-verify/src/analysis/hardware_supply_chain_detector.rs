#[derive(Debug, Clone, PartialEq)]
pub enum HardwareSupplyChainVulnerability {
    FirmwareCompromise { pc: usize, compromise_vector: String, description: String },
}

pub struct HardwareSupplyChainDetector { 
    bytecode: Vec<u8> 
}

impl HardwareSupplyChainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<HardwareSupplyChainVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect hardware RNG dependency
        if let Some(pc) = self.detect_hardware_rng_dependency() {
            vulnerabilities.push(HardwareSupplyChainVulnerability::FirmwareCompromise {
                pc,
                compromise_vector: "Hardware RNG Dependency".to_string(),
                description: "Contract relies on hardware RNG without software fallback, vulnerable to firmware backdoors".to_string(),
            });
        }
        
        // Detect HSM dependency without verification
        if let Some(pc) = self.detect_unverified_hsm_trust() {
            vulnerabilities.push(HardwareSupplyChainVulnerability::FirmwareCompromise {
                pc,
                compromise_vector: "HSM Trust Without Verification".to_string(),
                description: "Contract trusts HSM/enclave without remote attestation, vulnerable to supply chain attacks".to_string(),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_hardware_rng_dependency(&self) -> Option<usize> {
        // Look for PREVRANDAO or similar without fallback
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x44 { // PREVRANDAO (or DIFFICULTY in older versions)
                let mut has_fallback = false;
                
                // Check for alternative RNG source
                for j in i..i.saturating_add(15).min(self.bytecode.len()) {
                    // BLOCKHASH or KECCAK256-based fallback
                    if self.bytecode[j] == 0x40 || self.bytecode[j] == 0x20 { // BLOCKHASH or KECCAK256
                        has_fallback = true;
                    }
                }
                
                // Used in critical operation without fallback
                if !has_fallback {
                    for j in i..i.saturating_add(15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (storing hardware RNG)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
    
    fn detect_unverified_hsm_trust(&self) -> Option<usize> {
        // Look for signature verification without attestation checks
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // ECRECOVER precompile (address 0x01)
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 { // Address 0x01
                    // Check for attestation verification (multiple signature checks)
                    let mut sig_checks = 0;
                    for j in (i.saturating_sub(20)..i+20).step_by(1) {
                        if j < self.bytecode.len() && self.bytecode[j] == 0x60 {
                            if j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x01 {
                                sig_checks += 1;
                            }
                        }
                    }
                    
                    // Single signature check without attestation
                    if sig_checks == 1 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
