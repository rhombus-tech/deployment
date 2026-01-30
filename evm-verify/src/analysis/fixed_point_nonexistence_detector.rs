use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixedPointConvergenceVulnerability {
    NoConvergence { description: String, location: usize, confidence: f32 },
    OscillatingUpdate { description: String, location: usize, confidence: f32 },
    UnboundedIteration { description: String, location: usize, confidence: f32 },
}

pub struct FixedPointNonExistenceDetector {
    bytecode: Vec<u8>,
}

impl FixedPointNonExistenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<FixedPointConvergenceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            
            // Pattern 1: Iterative update without convergence check
            let has_iteration = section.windows(15).any(|w| {
                w.contains(&0x57) && w.contains(&0x55) // JUMPI + SSTORE (iterative update)
            });
            
            let no_delta_check = !section.windows(15).any(|w| {
                w.contains(&0x03) && w.contains(&0x10) // SUB + LT (check if converged)
            });
            
            if has_iteration && no_delta_check {
                vulnerabilities.push(FixedPointConvergenceVulnerability::NoConvergence {
                    description: format!("Fixed point non-existence at PC {}. Iterative update without convergence guarantee. Attack: Update function has no fixed point → oscillates forever or diverges. Brouwer fixed point theorem: Continuous function on compact convex set has fixed point. Violation → no equilibrium. Example: Price oracle updates price = f(price) but f has no fixed point → never settles. Or: Rebalancing function overshoots → perpetual oscillation. Mitigation: Prove convergence (Banach fixed point), add damping factor, or limit iterations.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
            
            // Pattern 2: State that alternates (oscillation)
            let has_toggle = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x15) && w.contains(&0x55) // SLOAD + ISZERO + SSTORE (toggle)
            });
            
            if has_toggle && has_iteration {
                vulnerabilities.push(FixedPointConvergenceVulnerability::OscillatingUpdate {
                    description: format!("Oscillating state at PC {}. State flips between values without settling. Attack: System toggles A→B→A→B... never reaches equilibrium. Example: AMM price oscillates around true price, exploited via sandwich at each oscillation. Or: Governance vote flips → no decision reached. Dynamical systems: Limit cycle instead of fixed point. Mitigation: Add hysteresis, dampening, or require supermajority for state changes.", i),
                    location: i,
                    confidence: 0.79,
                });
            }
            
            // Pattern 3: Loop without termination guarantee
            let has_while_loop = section.windows(20).any(|w| {
                w.contains(&0x57) && !w.windows(10).any(|w2| {
                    w2.contains(&0x60) // PUSH1 (loop counter)
                })
            });
            
            if has_while_loop {
                vulnerabilities.push(FixedPointConvergenceVulnerability::UnboundedIteration {
                    description: format!("Unbounded iteration at PC {}. While loop without proven termination. Attack: Loop may never terminate → infinite gas consumption → revert. Halting problem: Can't decide if loop halts in general. Example: while(condition) without condition → false guarantee. Turing complete → undecidable. Mitigation: For loops with known bounds, add iteration limit, or prove loop invariant guarantees termination.", i),
                    location: i,
                    confidence: 0.77,
                });
            }
        }
        
        vulnerabilities
    }
}
