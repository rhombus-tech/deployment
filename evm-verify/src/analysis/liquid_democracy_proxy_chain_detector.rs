use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidDemocracyProxyChainVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct LiquidDemocracyProxyChainDetector {
    bytecode: Vec<u8>,
}

impl LiquidDemocracyProxyChainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidDemocracyProxyChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Liquid democracy allows vote delegation through chains
        // Detect unbounded delegation chain traversal
        if let Some(location) = self.has_unbounded_delegation_chain() {
            vulnerabilities.push(LiquidDemocracyProxyChainVulnerability {
                vulnerability_type: "Liquid Democracy Unbounded Delegation Chain".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Vote delegation follows unbounded chain without depth limit. Long delegation chains can cause DoS via gas exhaustion or enable circular delegation attacks. Implement maximum chain depth (e.g., 10 hops).".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect circular delegation risk
        if let Some(location) = self.has_circular_delegation_risk() {
            vulnerabilities.push(LiquidDemocracyProxyChainVulnerability {
                vulnerability_type: "Liquid Democracy Circular Delegation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Delegation chain traversal without cycle detection. Circular delegations (A→B→A) cause infinite loops or incorrect vote counting. Implement visited tracking with mapping.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect delegation chain manipulation
        if let Some(location) = self.has_delegation_chain_manipulation() {
            vulnerabilities.push(LiquidDemocracyProxyChainVulnerability {
                vulnerability_type: "Liquid Democracy Chain Manipulation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Delegation can be changed after vote counting starts. Attackers can redirect vote chains mid-proposal to manipulate outcomes. Lock delegations during active proposals.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_unbounded_delegation_chain(&self) -> Option<usize> {
        // Pattern: Recursive delegation lookup without depth counter
        // Look for loop pattern (JUMPDEST + SLOAD delegation) without counter decrement
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                // Look for delegation SLOAD in loop
                let mut has_delegation_load = false;
                let mut has_depth_counter = false;
                
                for j in i+1..i+50.min(self.bytecode.len()) {
                    // Delegation lookup pattern
                    if self.bytecode[j] == 0x54 { // SLOAD (reading delegation)
                        has_delegation_load = true;
                    }
                    // Check for depth counter (SUB with counter)
                    if self.bytecode[j] == 0x03 { // SUB (decrementing counter)
                        // Check if followed by ISZERO (checking if zero)
                        for k in j+1..(j+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO
                                has_depth_counter = true;
                                break;
                            }
                        }
                    }
                    // Loop back (JUMPI)
                    if self.bytecode[j] == 0x57 && has_delegation_load && !has_depth_counter {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_circular_delegation_risk(&self) -> Option<usize> {
        // Pattern: Delegation traversal without visited set tracking
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (delegation loop)
                // Look for delegation loading
                let mut has_delegation_traversal = false;
                let mut has_visited_tracking = false;
                
                for j in (i+1)..(i+60).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD (delegation lookup)
                        has_delegation_traversal = true;
                    }
                    // Check for visited tracking (additional SLOAD/SSTORE for visited set)
                    // Pattern: Current address stored in visited mapping
                    if self.bytecode[j] == 0x55 { // SSTORE (marking as visited)
                        // Check if this is tracking pattern (SHA3 for mapping)
                        for k in j.saturating_sub(10)..j {
                            if self.bytecode[k] == 0x20 { // SHA3 (visited mapping key)
                                has_visited_tracking = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_delegation_traversal && !has_visited_tracking {
                    return Some(i);
                }
            }
        }
        None
    }

    fn has_delegation_chain_manipulation(&self) -> Option<usize> {
        // Pattern: Delegation change (SSTORE) without proposal state check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (setting delegation)
                // Check if proposal state is validated
                let mut has_proposal_state_check = false;
                
                for j in i.saturating_sub(35)..i {
                    // Look for proposal state loading
                    if self.bytecode[j] == 0x54 { // SLOAD (proposal state)
                        // Check if followed by comparison (active check)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 { // EQ (checking state)
                                has_proposal_state_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_proposal_state_check {
                    // Verify this is delegation-related (preceded by address operations)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x33 { // CALLER (delegator)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
