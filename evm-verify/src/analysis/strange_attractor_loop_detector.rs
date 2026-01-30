use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StrangeAttractorVulnerability {
    ChaoticOscillation { description: String, location: usize, confidence: f32 },
    NeverSettlingState { description: String, location: usize, confidence: f32 },
    PeriodicLimitCycle { description: String, location: usize, confidence: f32 },
}

pub struct StrangeAttractorLoopDetector {
    bytecode: Vec<u8>,
}

impl StrangeAttractorLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<StrangeAttractorVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            let section = &self.bytecode[i..std::cmp::min(i + 120, self.bytecode.len())];
            
            // Pattern 1: State update in loop with no damping
            let has_loop = section.windows(15).any(|w| w.contains(&0x56) || w.contains(&0x57)); // JUMP/JUMPI
            let has_state_update = section.windows(20).any(|w| {
                w.contains(&0x54) && w.contains(&0x55) // SLOAD + SSTORE
            });
            let has_arithmetic = section.windows(10).any(|w| {
                w.contains(&0x01) || w.contains(&0x03) || w.contains(&0x02) // ADD/SUB/MUL
            });
            let no_damping = !section.windows(15).any(|w| {
                // No division or modulo that would provide damping
                w.contains(&0x04) || w.contains(&0x06)
            });
            
            if has_loop && has_state_update && has_arithmetic && no_damping {
                vulnerabilities.push(StrangeAttractorVulnerability::ChaoticOscillation {
                    description: format!("Strange attractor at PC {}. State oscillates chaotically, never settles. Attack: System enters chaotic regime → unpredictable behavior → exploitation windows. Chaos theory: Strange attractor = long-term behavior neither fixed point nor periodic. Lorenz attractor: weather system never repeats. Here: price = f(price) where f has no stable fixed point. Example: AMM with feedback → price bounces $100→$110→$95→$105→$98→... forever. Real: Algorithmic stablecoin death spirals (Terra/Luna $40B), reflexive pricing loops. Mitigation: Add damping factor (multiply by 0.99), impose convergence requirement, or use PID controller.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
            
            // Pattern 2: Oscillating state between two values
            let has_toggle = section.windows(20).any(|w| {
                w.contains(&0x15) && w.contains(&0x55) // ISZERO + SSTORE (toggle pattern)
            });
            let has_conditional_jump = section.windows(15).any(|w| {
                w.contains(&0x57) // JUMPI
            });
            
            if has_toggle && has_loop && has_conditional_jump {
                vulnerabilities.push(StrangeAttractorVulnerability::PeriodicLimitCycle {
                    description: format!("Periodic limit cycle at PC {}. State alternates between values in loop. Attack: System oscillates A→B→A→B... infinitely. Dynamical systems: Limit cycle = closed trajectory. Van der Pol oscillator = periodic. Example: Governance vote flips approve→reject→approve→reject. Or: Liquidation threshold crossed → liquidate → price recovers → re-collateralize → price drops → liquidate... MEV extraction at each cycle. Mitigation: Hysteresis (require 5% buffer), time delays between state changes, or supermajority for reversals.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
            
            // Pattern 3: Feedback loop without convergence check
            let has_comparison = section.windows(15).any(|w| {
                w.contains(&0x10) || w.contains(&0x11) || w.contains(&0x14) // LT/GT/EQ
            });
            let no_convergence_check = !section.windows(20).any(|w| {
                // No check for |new - old| < threshold
                w.contains(&0x03) && w.contains(&0x10) // SUB + LT (delta check)
            });
            
            if has_loop && has_state_update && has_comparison && no_convergence_check {
                vulnerabilities.push(StrangeAttractorVulnerability::NeverSettlingState {
                    description: format!("Never-settling state at PC {}. Iterative update without convergence guarantee. Attack: System runs iteration forever or reverts after gas exhaustion. Example: Newton-Raphson root finding without convergence check → oscillates around root but never reaches it. Price oracle: while(true) {{price = updatePrice(price)}} but updatePrice() has no fixed point. Chaos: Iterative map f(x) = f(f(x)) may not converge. Mitigation: Add max iterations (e.g., 100), check |x_new - x_old| < epsilon, or prove Banach fixed-point theorem conditions.", i),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
}
