/// Weakness Chain Synthesizer
/// Combines minor weaknesses into critical vulnerabilities
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct WeaknessChainSynthesizer {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WeaknessChain {
    pub weaknesses: Vec<Weakness>,
    pub combined_severity: SecuritySeverity,
    pub chain_score: f32,
}

#[derive(Debug, Clone)]
pub struct Weakness {
    pub weakness_type: String,
    pub location: usize,
    pub individual_severity: SecuritySeverity,
}

impl WeaknessChainSynthesizer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn synthesize_chains(&self, weaknesses: &[Weakness]) -> Vec<WeaknessChain> {
        let mut chains = Vec::new();

        // Find chains where multiple weaknesses compound
        for i in 0..weaknesses.len() {
            for j in (i+1)..weaknesses.len() {
                if self.are_chainable(&weaknesses[i], &weaknesses[j]) {
                    let chain_score = self.calculate_chain_impact(&[weaknesses[i].clone(), weaknesses[j].clone()]);
                    
                    chains.push(WeaknessChain {
                        weaknesses: vec![weaknesses[i].clone(), weaknesses[j].clone()],
                        combined_severity: self.escalate_severity(&weaknesses[i].individual_severity),
                        chain_score,
                    });
                }
            }
        }

        chains
    }

    fn are_chainable(&self, w1: &Weakness, w2: &Weakness) -> bool {
        // Weaknesses are chainable if they're within 100 bytes
        w1.location.abs_diff(w2.location) < 100
    }

    fn calculate_chain_impact(&self, weaknesses: &[Weakness]) -> f32 {
        // Impact increases non-linearly with chain length
        (weaknesses.len() as f32).powf(1.5) * 0.3
    }

    fn escalate_severity(&self, severity: &SecuritySeverity) -> SecuritySeverity {
        // Chain escalates severity by one level
        match severity {
            SecuritySeverity::Low => SecuritySeverity::Medium,
            SecuritySeverity::Medium => SecuritySeverity::High,
            SecuritySeverity::High => SecuritySeverity::Critical,
            SecuritySeverity::Critical => SecuritySeverity::Critical,
            _ => SecuritySeverity::Low,
        }
    }

    pub fn find_amplifying_combinations(&self) -> Vec<(String, String, f32)> {
        // Known weakness combinations that amplify each other
        vec![
            ("Reentrancy".to_string(), "Unchecked Return".to_string(), 2.5),
            ("Integer Overflow".to_string(), "Price Manipulation".to_string(), 3.0),
            ("Access Control".to_string(), "Delegatecall".to_string(), 4.0),
        ]
    }
}
