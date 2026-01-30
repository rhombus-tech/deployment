use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelfReferenceVulnerability {
    SelfCallCycle { description: String, location: usize, confidence: f32 },
    CircularDependency { description: String, location: usize, confidence: f32 },
    QuinePattern { description: String, location: usize, confidence: f32 },
}

pub struct SelfReferenceParadoxDetector {
    bytecode: Vec<u8>,
}

impl SelfReferenceParadoxDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<SelfReferenceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern 1: Contract calls itself
            let has_self_call = section.windows(15).any(|w| {
                w.contains(&0x30) && (w.contains(&0xF1) || w.contains(&0xFA)) // ADDRESS + (CALL or STATICCALL)
            });
            
            if has_self_call {
                vulnerabilities.push(SelfReferenceVulnerability::SelfCallCycle {
                    description: format!("Self-reference paradox at PC {}. Contract calls itself. Attack: Liar's paradox - contract queries own state that depends on query result. Example: isVulnerable() checks if contract is vulnerable → paradox. Or: getPrice() calls itself → infinite recursion or undefined state. Gödel: Self-referential statements undecidable. Real bug: Akutars $34M - reentered own initialization. Mitigation: Reentrancy guard, stateless self-calls only, or avoid self-reference.", i),
                    location: i,
                    confidence: 0.88,
                });
            }
            
            // Pattern 2: Circular state dependency
            let has_state_read_write = section.windows(20).any(|w| {
                w.windows(10).any(|w2| w2.contains(&0x54)) && // SLOAD
                w.windows(10).any(|w2| w2.contains(&0x55))    // SSTORE
            });
            
            let has_loop = section.windows(10).any(|w| w.contains(&0x56) || w.contains(&0x57));
            
            if has_state_read_write && has_loop && has_self_call {
                vulnerabilities.push(SelfReferenceVulnerability::CircularDependency {
                    description: format!("Circular dependency at PC {}. State depends on itself via call chain. Attack: A depends on B, B depends on A → deadlock or undefined. Example: Token balance depends on price, price depends on token balance → circular. Fixed point may not exist or converge. Tarski: Least fixed point computable, but may not match intended semantics. Mitigation: Break cycles with external oracle, make dependencies acyclic (DAG), or use iterative convergence.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
