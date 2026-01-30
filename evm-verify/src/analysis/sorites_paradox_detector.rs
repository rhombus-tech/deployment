use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoritesParadoxVulnerability {
    GradualParameterDrift { description: String, location: usize, confidence: f32 },
    VagueBoundaryExploitation { description: String, location: usize, confidence: f32 },
    IncrementalStateChange { description: String, location: usize, confidence: f32 },
}

pub struct SoritesParadoxDetector {
    bytecode: Vec<u8>,
}

impl SoritesParadoxDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<SoritesParadoxVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(90) {
            let section = &self.bytecode[i..std::cmp::min(i + 90, self.bytecode.len())];
            
            // Pattern 1: Small incremental changes without total bounds
            let has_increment = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x01) && w.contains(&0x55) // SLOAD + ADD + SSTORE
            });
            let has_small_constant = section.windows(5).any(|w| {
                w.contains(&0x60) // PUSH1 (small number)
            });
            let no_total_check = !section.windows(20).any(|w| {
                w.contains(&0x10) && w.contains(&0x60) // LT + PUSH (total < max)
            });
            
            if has_increment && has_small_constant && no_total_check {
                vulnerabilities.push(SoritesParadoxVulnerability::GradualParameterDrift {
                    description: format!("Sorites paradox at PC {}. Gradual parameter changes without cumulative bounds. Attack: Make many small changes that individually seem fine but cumulatively are massive. Philosophy: How many grains make a heap? Remove one grain → still a heap. Repeat → eventually not a heap, but when? No clear boundary. Example: Increase fee by 0.01% 1000 times → 10% total increase but each change is 'negligible'. Or: Slow rug pull by incrementing withdrawal fees. Real: Parameter drift attacks, governance manipulation via many small proposals. Mitigation: Check cumulative change from initial value, set absolute bounds, or require supermajority for repeated changes.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
            
            // Pattern 2: Threshold checks without hysteresis
            let has_threshold = section.windows(15).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI (threshold check)
            });
            let no_buffer = !section.windows(20).any(|w| {
                w.contains(&0x01) || w.contains(&0x03) // ADD/SUB (add buffer)
            });
            
            if has_threshold && no_buffer && has_increment {
                vulnerabilities.push(SoritesParadoxVulnerability::VagueBoundaryExploitation {
                    description: format!("Vague boundary at PC {}. Threshold without hysteresis exploitable. Attack: Oscillate around threshold, trigger state flip repeatedly. Example: Liquidation at collateral ratio = 1.5. Attacker keeps ratio at 1.500001 → tiny drop triggers liquidation → MEV. Sorites: Where exactly is the boundary? 1.5000? 1.5001? Vague. Exploiter: Use vagueness to game system. Real: Liquidation threshold hunting, oracle manipulation near tipping points, auction sniping. Mitigation: Hysteresis (threshold up = 1.6, threshold down = 1.4), grace periods, or randomize threshold slightly.", i),
                    location: i,
                    confidence: 0.80,
                });
            }
            
            // Pattern 3: Cumulative small changes affecting critical behavior
            let has_mul_or_div = section.windows(10).any(|w| {
                w.contains(&0x02) || w.contains(&0x04) // MUL or DIV
            });
            let has_conditional = section.windows(15).any(|w| {
                w.contains(&0x57) // JUMPI
            });
            
            if has_increment && has_mul_or_div && has_conditional {
                vulnerabilities.push(SoritesParadoxVulnerability::IncrementalStateChange {
                    description: format!("Incremental state change at PC {}. Many small updates compound non-linearly. Attack: Each change is ε small, but N changes = Nε can be large. Or: Non-linear effects → ε changes compound to ε². Example: Balance updates with fees. Each tx: fee = 0.1%. After 1000 txs: balance * 0.999^1000 = 36% loss! Each 0.1% seemed fine. Sorites: Is 0.1% fee significant? No. Is 0.1% × 1000 significant? Yes! But when did it become significant? Mitigation: Cap cumulative fees, warn on repeated small changes, or reset baseline periodically.", i),
                    location: i,
                    confidence: 0.78,
                });
            }
        }
        
        vulnerabilities
    }
}
