use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaxTokenManipulationVulnerability {
    HiddenTransferTax { description: String, location: usize, confidence: f32 },
    VariableTaxRate { description: String, location: usize, confidence: f32 },
    TaxBypassForOwner { description: String, location: usize },
    ExcessiveTaxRate { description: String, location: usize, tax_rate: u32 },
}

pub struct TaxTokenManipulationDetector {
    bytecode: Vec<u8>,
}

impl TaxTokenManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TaxTokenManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // transfer selector: 0xa9059cbb
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == transfer_selector) {
                // Check for fee/tax calculation in transfer
                if self.has_fee_calculation(i, i + 100) {
                    if !self.discloses_tax(i, i + 100) {
                        vulnerabilities.push(TaxTokenManipulationVulnerability::HiddenTransferTax {
                            description: "Hidden transfer tax/fee without event emission or documentation".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                    
                    if self.has_variable_tax(i, i + 100) {
                        vulnerabilities.push(TaxTokenManipulationVulnerability::VariableTaxRate {
                            description: "Tax rate can be changed dynamically by owner - rug pull risk".to_string(),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                    
                    if self.has_tax_exemption(i, i + 100) {
                        vulnerabilities.push(TaxTokenManipulationVulnerability::TaxBypassForOwner {
                            description: "Owner/special addresses bypass transfer tax".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_fee_calculation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Fee calculation: MUL followed by DIV (percentage calculation)
        let mul_positions: Vec<_> = self.bytecode[start..range_end]
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x02) // MUL
            .map(|(i, _)| i)
            .collect();
        
        for pos in mul_positions {
            let check_end = (pos + 5).min(range_end - start);
            if self.bytecode[start + pos..start + check_end].iter().any(|&b| b == 0x04) {
                return true; // MUL followed by DIV
            }
        }
        false
    }
    
    fn discloses_tax(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Event emission (LOG opcodes)
        self.bytecode[start..range_end].iter().any(|&b| b >= 0xA0 && b <= 0xA4)
    }
    
    fn has_variable_tax(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Tax rate loaded from storage (SLOAD)
        self.bytecode[start..range_end].iter().any(|&b| b == 0x54)
    }
    
    fn has_tax_exemption(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for CALLER comparison (owner check) before fee calc
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_caller && has_eq
    }
}
