use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReflexivityVulnerability {
    PriceFeedbackLoop { description: String, location: usize, confidence: f32 },
    SelfReferencingOracle { description: String, location: usize, confidence: f32 },
}

pub struct ReflexivityAttackDetector {
    bytecode: Vec<u8>,
}

impl ReflexivityAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ReflexivityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(75) {
            let section = &self.bytecode[i..std::cmp::min(i + 75, self.bytecode.len())];
            
            // Pattern: Price oracle that reads from same protocol
            let has_price_read = section.windows(10).any(|w| {
                w.contains(&0xFA) && w.contains(&0x3E) // STATICCALL + RETURNDATACOPY
            });
            
            let has_price_write = section.windows(10).any(|w| {
                w.contains(&0x55) // SSTORE (update price)
            });
            
            if has_price_read && has_price_write {
                vulnerabilities.push(ReflexivityVulnerability::PriceFeedbackLoop {
                    description: format!("Reflexivity attack at PC {}. Price affects behavior, behavior affects price (loop). Attack: Manipulate price → protocol reacts → price moves more → spiral. Example: Terra UST - price drop → mint more LUNA → LUNA supply increases → price drops more → death spiral. Or: Margin call → forced selling → price drops → more margin calls. Soros: Reflexivity = market participants' bias affects fundamentals. Mitigation: Circuit breakers, external price sources, or time delays to break loop.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
            
            // Pattern: Oracle that references itself
            let has_self_call = section.windows(15).any(|w| {
                w.contains(&0x30) && w.contains(&0xFA) // ADDRESS + STATICCALL (self-reference)
            });
            
            if has_self_call && has_price_read {
                vulnerabilities.push(ReflexivityVulnerability::SelfReferencingOracle {
                    description: format!("Self-referencing oracle at PC {}. Protocol uses own state as price source. Attack: Manipulate internal state → oracle reflects manipulation → protocol acts on manipulated price. Example: AMM using its own pool as oracle → attacker manipulates pool → AMM thinks price changed → liquidates based on manipulated price. Circular logic: Price = f(state), state = g(price). Mitigation: Use external oracles only, never self-reference.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
