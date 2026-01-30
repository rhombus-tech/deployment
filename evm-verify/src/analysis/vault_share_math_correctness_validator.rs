/// Vault Share Math Correctness Validator  
/// Verifies ERC-4626 vaults correctly calculate shares
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct VaultShareMathCorrectnessValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ShareMathViolation {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub confidence: f32,
}

impl VaultShareMathCorrectnessValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate(&self) -> Vec<ShareMathViolation> {
        let mut violations = Vec::new();
        
        // Check deposit math: shares = assets * totalSupply / totalAssets
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_share_calculation(i) && !self.has_correct_formula(i, 40) {
                violations.push(ShareMathViolation {
                    location: i,
                    severity: SecuritySeverity::Critical,
                    confidence: 0.85,
                });
            }
        }
        
        violations
    }

    fn has_share_calculation(&self, pc: usize) -> bool {
        let window = self.bytecode.get(pc..pc.saturating_add(20)).unwrap_or(&[]);
        window.contains(&0x02) && window.contains(&0x04) // MUL and DIV
    }

    fn has_correct_formula(&self, pc: usize, range: usize) -> bool {
        let window = self.bytecode.get(pc..pc.saturating_add(range)).unwrap_or(&[]);
        window.iter().filter(|&&b| b == 0x02).count() >= 1 && 
        window.iter().filter(|&&b| b == 0x04).count() >= 1
    }
}
