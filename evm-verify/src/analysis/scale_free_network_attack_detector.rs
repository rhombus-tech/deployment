#[derive(Debug, Clone, PartialEq)]
pub enum ScaleFreeNetworkVulnerability {
    HubRemoval { pc: usize, network_vulnerability: f64, description: String },
}

pub struct ScaleFreeNetworkAttackDetector { 
    bytecode: Vec<u8> 
}

impl ScaleFreeNetworkAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { 
        Self { bytecode } 
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ScaleFreeNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect single critical contract dependency (hub)
        if let Some((pc, centrality)) = self.detect_single_hub_dependency() {
            vulnerabilities.push(ScaleFreeNetworkVulnerability::HubRemoval {
                pc,
                network_vulnerability: centrality,
                description: format!(
                    "Contract has critical dependency on single external contract (hub). \
                    Centrality score: {:.2}. Hub failure would break entire system.", 
                    centrality
                ),
            });
        }
        
        // Detect oracle hub dependency
        if let Some((pc, centrality)) = self.detect_oracle_hub() {
            vulnerabilities.push(ScaleFreeNetworkVulnerability::HubRemoval {
                pc,
                network_vulnerability: centrality,
                description: format!(
                    "Single oracle acts as hub for all price data. \
                    Centrality score: {:.2}. Oracle failure creates systemic risk.", 
                    centrality
                ),
            });
        }
        
        // Detect governance hub
        if let Some((pc, centrality)) = self.detect_governance_hub() {
            vulnerabilities.push(ScaleFreeNetworkVulnerability::HubRemoval {
                pc,
                network_vulnerability: centrality,
                description: format!(
                    "Single governance contract controls critical parameters. \
                    Centrality score: {:.2}. Compromise would affect entire protocol.", 
                    centrality
                ),
            });
        }
        
        vulnerabilities
    }
    
    fn detect_single_hub_dependency(&self) -> Option<(usize, f64)> {
        let mut external_calls = Vec::new();
        let mut target_addresses = Vec::new();
        
        // Collect all external CALL operations
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if matches!(self.bytecode[i], 0xf1 | 0xf2 | 0xf4 | 0xfa) { // CALL, CALLCODE, DELEGATECALL, STATICCALL
                external_calls.push(i);
                
                // Try to extract target address (look backward for PUSH20)
                for j in (i.saturating_sub(25)..i).rev() {
                    if self.bytecode[j] == 0x73 && j + 20 < self.bytecode.len() { // PUSH20
                        let addr_bytes = &self.bytecode[j+1..j+21];
                        target_addresses.push(addr_bytes.to_vec());
                        break;
                    }
                }
            }
        }
        
        if external_calls.len() < 3 {
            return None; // Too few calls to determine hub
        }
        
        // Check if all calls go to same address (hub)
        if !target_addresses.is_empty() {
            let first_addr = &target_addresses[0];
            let same_target_count = target_addresses.iter()
                .filter(|addr| *addr == first_addr)
                .count();
            
            // If >70% of calls go to same address, it's a hub
            let centrality = same_target_count as f64 / target_addresses.len() as f64;
            if centrality > 0.7 {
                return Some((external_calls[0], centrality));
            }
        }
        
        None
    }
    
    fn detect_oracle_hub(&self) -> Option<(usize, f64)> {
        let mut oracle_calls = Vec::new();
        let mut oracle_addresses = Vec::new();
        
        // Look for oracle function signatures
        let oracle_sigs = [
            [0x50, 0xd2, 0x5b, 0xcd], // latestAnswer()
            [0xfe, 0xaf, 0x96, 0x8c], // latestRoundData()
            [0xb5, 0xab, 0x58, 0xdc], // getPrice()
        ];
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for PUSH4 with oracle signature
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let sig = &self.bytecode[i+1..i+5];
                if oracle_sigs.iter().any(|os| os == sig) {
                    // Found oracle call, look for STATICCALL nearby
                    for j in i..i.saturating_add(20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_calls.push(i);
                            
                            // Extract target address
                            for k in (i.saturating_sub(25)..i).rev() {
                                if self.bytecode[k] == 0x73 && k + 20 < self.bytecode.len() {
                                    oracle_addresses.push(self.bytecode[k+1..k+21].to_vec());
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        if oracle_calls.len() < 2 {
            return None;
        }
        
        // Check if all oracle calls use same address
        if !oracle_addresses.is_empty() {
            let first_oracle = &oracle_addresses[0];
            let same_oracle_count = oracle_addresses.iter()
                .filter(|addr| *addr == first_oracle)
                .count();
            
            let centrality = same_oracle_count as f64 / oracle_addresses.len() as f64;
            if centrality > 0.8 { // Higher threshold for oracles
                return Some((oracle_calls[0], centrality));
            }
        }
        
        None
    }
    
    fn detect_governance_hub(&self) -> Option<(usize, f64)> {
        // Look for patterns where single address controls multiple critical operations
        let mut governance_checks = 0;
        let mut first_check_pc = None;
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Pattern: CALLER -> PUSH20 address -> EQ -> require pattern
            if self.bytecode[i] == 0x33 { // CALLER
                let mut found_address_check = false;
                
                for j in i..i.saturating_add(12).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x73 && j + 20 < self.bytecode.len() { // PUSH20
                        // Look for EQ comparison
                        for k in j..j.saturating_add(5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ
                                found_address_check = true;
                                governance_checks += 1;
                                if first_check_pc.is_none() {
                                    first_check_pc = Some(i);
                                }
                                break;
                            }
                        }
                    }
                    if found_address_check {
                        break;
                    }
                }
            }
        }
        
        // If multiple governance checks to same address (hub pattern)
        if governance_checks >= 3 {
            let centrality = 0.9; // High centrality for governance hub
            return Some((first_check_pc.unwrap(), centrality));
        }
        
        None
    }
}
