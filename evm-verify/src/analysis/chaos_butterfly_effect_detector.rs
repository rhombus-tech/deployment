use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosButterflyVulnerability {
    SensitiveDependence { description: String, location: usize, confidence: f32 },
    ExponentialDivergence { description: String, location: usize, confidence: f32 },
    SmallInputMassiveOutput { description: String, location: usize, confidence: f32 },
}

pub struct ChaosButterflyEffectDetector {
    bytecode: Vec<u8>,
}

impl ChaosButterflyEffectDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ChaosButterflyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern 1: Exponential/power operations on user input
            let has_exp = section.windows(10).any(|w| w.contains(&0x0A)); // EXP opcode
            let has_mul_chain = section.windows(20).filter(|w| w.contains(&0x02)).count() >= 3; // Multiple MUL
            let has_calldataload = section.contains(&0x35); // CALLDATALOAD
            
            if (has_exp || has_mul_chain) && has_calldataload {
                vulnerabilities.push(ChaosButterflyVulnerability::ExponentialDivergence {
                    description: format!("Chaos butterfly effect at PC {}. Exponential sensitivity to input. Attack: Tiny input difference (1 wei) → massive state divergence (millions). Chaos theory: dx/dt = λx → exponential growth. Lyapunov exponent λ > 0 = chaos. Example: Price = input^10 → 1.01^10 = 1.10 (10% change from 0.01% input). Mango Markets $110M: Small oracle tweak → massive position liquidation cascade. Mitigation: Bound amplification factor, use logarithmic scaling, or limit input sensitivity to linear.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
            
            // Pattern 2: Recursive multiplication/division chains
            let has_div_mul_chain = section.windows(30).any(|w| {
                let div_count = w.windows(5).filter(|x| x.contains(&0x04)).count(); // DIV
                let mul_count = w.windows(5).filter(|x| x.contains(&0x02)).count(); // MUL
                div_count + mul_count >= 5
            });
            
            if has_div_mul_chain && has_calldataload {
                vulnerabilities.push(ChaosButterflyVulnerability::SmallInputMassiveOutput {
                    description: format!("Small input massive output at PC {}. Compounding operations amplify tiny changes. Attack: Input changes by 0.1% → output changes by 1000%. Example: for(i=0;i<100;i++) {{x = x * (1 + input/10000)}} → 0.01% input change → 10% output change after 100 iterations. Real: Compound interest calculations, bonding curves, AMM price updates. Mitigation: Cap iteration count, use fixed-point with overflow checks, or limit compounding depth.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
            
            // Pattern 3: Division by small numbers (near-zero denominators)
            let has_div = section.contains(&0x04); // DIV
            let has_comparison = section.windows(10).any(|w| {
                (w.contains(&0x10) || w.contains(&0x11)) // LT or GT
            });
            
            if has_div && !has_comparison && has_calldataload {
                vulnerabilities.push(ChaosButterflyVulnerability::SensitiveDependence {
                    description: format!("Sensitive dependence at PC {}. Division without zero-check amplifies small changes. Attack: Denominator near zero → output explodes. Example: price = reserves1 / reserves2. If reserves2 drops from 100 to 1 → price increases 100x. Chaos: Small change in initial condition → vastly different outcome. Lorenz attractor: weather prediction impossible after days. Here: price prediction impossible with small liquidity changes. Mitigation: Minimum denominator threshold, check for near-zero, or use safe division with caps.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
        }
        
        vulnerabilities
    }
}
