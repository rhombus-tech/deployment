use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SqrtNewtonNonconvergenceVulnerability {
    NoConvergenceCheck {
        description: String,
        location: usize,
        confidence: f32,
    },
    InsufficientIterations {
        description: String,
        location: usize,
        iterations: u32,
    },
}

pub struct SqrtNewtonNonconvergenceDetector {
    bytecode: Vec<u8>,
}

impl SqrtNewtonNonconvergenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SqrtNewtonNonconvergenceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.is_sqrt_newton_method(i) {
                let has_convergence_check = self.checks_convergence(i, i + 200);
                
                if !has_convergence_check {
                    vulnerabilities.push(SqrtNewtonNonconvergenceVulnerability::NoConvergenceCheck {
                        description: "Square root Newton method without convergence validation".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if let Some(iters) = self.count_iterations(i, i + 200) {
                    if iters < 5 {
                        vulnerabilities.push(SqrtNewtonNonconvergenceVulnerability::InsufficientIterations {
                            description: format!("Only {} iterations may not converge for all inputs", iters),
                            location: i,
                            iterations: iters,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_sqrt_newton_method(&self, location: usize) -> bool {
        if location + 100 > self.bytecode.len() {
            return false;
        }
        
        let has_div = self.bytecode[location..location + 100].iter().filter(|&&b| b == 0x04).count() >= 2;
        let has_add = self.bytecode[location..location + 100].iter().any(|&b| b == 0x01);
        let has_loop = self.bytecode[location..location + 100].iter().any(|&b| b == 0x56);
        
        has_div && has_add && has_loop
    }
    
    fn checks_convergence(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(5).any(|w| {
            w.iter().any(|&b| b == 0x03) && w.iter().any(|&b| b == 0x10)
        })
    }
    
    fn count_iterations(&self, start: usize, end: usize) -> Option<u32> {
        let range_end = end.min(self.bytecode.len());
        
        let jumpdest_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x5b).count();
        
        if jumpdest_count > 0 {
            Some(jumpdest_count as u32)
        } else {
            None
        }
    }
}
