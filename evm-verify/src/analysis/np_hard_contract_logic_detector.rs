use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NPHardVulnerability {
    TravelingSalesmanPattern { description: String, location: usize, confidence: f32 },
    KnapsackProblem { description: String, location: usize, confidence: f32 },
    SubsetSumProblem { description: String, location: usize, confidence: f32 },
}

pub struct NPHardContractLogicDetector {
    bytecode: Vec<u8>,
}

impl NPHardContractLogicDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NPHardVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern 1: Optimization over permutations (TSP-like)
            let has_nested_loops = section.windows(20).filter(|w| w.contains(&0x57)).count() >= 3;
            let has_min_max = section.windows(10).any(|w| {
                (w.contains(&0x10) || w.contains(&0x11)) && w.contains(&0x57)
            });
            
            if has_nested_loops && has_min_max {
                vulnerabilities.push(NPHardVulnerability::TravelingSalesmanPattern {
                    description: format!("NP-hard logic at PC {}. Optimization over permutations detected. Attack: Problem requires exploring N! possibilities → computationally infeasible for N>20. Complexity theory: Traveling Salesman Problem is NP-complete. Verification: O(N!). Example: Auction finding optimal allocation, routing problem, matching problem. Even with gas limit, attempting NP-hard in contract = griefing vector. No efficient algorithm exists (unless P=NP). Mitigation: Use approximation algorithms, heuristics, or solve off-chain with ZK proof of solution.", i),
                    location: i,
                    confidence: 0.78,
                });
            }
            
            // Pattern 2: Subset sum or knapsack
            let has_sum_check = section.windows(15).any(|w| {
                w.contains(&0x01) && w.contains(&0x14) // ADD + EQ (sum check)
            });
            
            if has_nested_loops && has_sum_check {
                vulnerabilities.push(NPHardVulnerability::KnapsackProblem {
                    description: format!("Knapsack problem at PC {}. Subset selection to meet target. Attack: Knapsack is NP-complete → O(2^N) to solve. Example: Allocate N items to fit in capacity C. Or: Select subset of tokens worth exactly X. Verification requires checking all 2^N subsets. Gas exhaustion for N>30. Computational complexity: exponential. Mitigation: Greedy approximation, dynamic programming with limits, or off-chain optimization + on-chain verification.", i),
                    location: i,
                    confidence: 0.75,
                });
            }
        }
        
        vulnerabilities
    }
}
