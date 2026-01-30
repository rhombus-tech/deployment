#[derive(Debug, Clone, PartialEq)]
pub enum GeospatialVulnerability {
    GPSSpoofing { pc: usize, spoofing_feasibility: f64, description: String },
}

pub struct GeospatialAttackDetector { 
    bytecode: Vec<u8> 
}

impl GeospatialAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<GeospatialVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect unverified location data usage
        if let Some((pc, feasibility)) = self.detect_unverified_location_oracle() {
            vulnerabilities.push(GeospatialVulnerability::GPSSpoofing {
                pc,
                spoofing_feasibility: feasibility,
                description: format!(
                    "Contract trusts location data from oracle without cryptographic proof (spoofing feasibility: {:.2})",
                    feasibility
                ),
            });
        }
        
        // Detect single-source geolocation dependency
        if let Some((pc, feasibility)) = self.detect_single_geolocation_source() {
            vulnerabilities.push(GeospatialVulnerability::GPSSpoofing {
                pc,
                spoofing_feasibility: feasibility,
                description: format!(
                    "Contract depends on single geolocation source, vulnerable to spoofing (feasibility: {:.2})",
                    feasibility
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_unverified_location_oracle(&self) -> Option<(usize, f64)> {
        // Look for oracle calls without cryptographic verification
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle query)
                let mut has_location_sig = false;
                let mut lacks_verification = true;
                
                // Check for location-related function signatures
                for j in (i.saturating_sub(20)..i).rev() {
                    if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() { // PUSH4
                        let sig = &self.bytecode[j+1..j+5];
                        // getLocation, getCoordinates, verifyLocation signatures
                        if matches!(sig, [0xaa, 0x11, _, _] | [0xbb, 0x22, _, _] | [0xcc, 0x33, _, _]) {
                            has_location_sig = true;
                        }
                    }
                }
                
                // Check for cryptographic verification after oracle call
                if has_location_sig {
                    for j in i..i.saturating_add(25).min(self.bytecode.len()) {
                        // ECRECOVER or signature verification
                        if self.bytecode[j] == 0x60 && j + 1 < self.bytecode.len() {
                            if self.bytecode[j+1] == 0x01 { // Address 0x01 (ecrecover precompile)
                                lacks_verification = false;
                            }
                        }
                    }
                }
                
                if has_location_sig && lacks_verification {
                    // High feasibility without crypto verification
                    return Some((i, 0.9));
                }
            }
        }
        None
    }
    
    fn detect_single_geolocation_source(&self) -> Option<(usize, f64)> {
        // Look for geolocation checks without redundancy
        let mut geo_calls = Vec::new();
        let mut geo_addresses = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) { // CALL or STATICCALL
                // Check if this is a geo oracle call
                for j in (i.saturating_sub(30)..i).rev() {
                    if self.bytecode[j] == 0x73 && j + 20 < self.bytecode.len() { // PUSH20 (address)
                        let addr = &self.bytecode[j+1..j+21];
                        // Check if location-related based on nearby selectors
                        for k in j..i {
                            if self.bytecode[k] == 0x63 && k + 4 < self.bytecode.len() {
                                let sig = &self.bytecode[k+1..k+5];
                                if matches!(sig, [0xaa, 0x11, _, _] | [0xbb, 0x22, _, _]) {
                                    geo_calls.push(i);
                                    geo_addresses.push(addr.to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Check if all geo calls use same source (single point of failure)
        if !geo_addresses.is_empty() {
            let first_addr = &geo_addresses[0];
            let same_source = geo_addresses.iter().all(|addr| addr == first_addr);
            
            if same_source && geo_calls.len() >= 1 {
                // High feasibility with single source
                return Some((geo_calls[0], 0.85));
            }
        }
        
        None
    }
}
