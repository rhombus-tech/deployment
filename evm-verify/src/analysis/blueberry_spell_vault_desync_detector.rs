use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlueberryVulnerability {
    SpellVaultStateDesync { description: String, location: usize, confidence: f32 },
    LeveragePositionManipulation { description: String, location: usize, confidence: f32 },
}

pub struct BlueberrySpellVaultDesyncDetector {
    bytecode: Vec<u8>,
}

impl BlueberrySpellVaultDesyncDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BlueberryVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Blueberry Protocol: Leverage yield farming
        // Vault holds position, Spell contract executes strategies
        // Risk: Vault and Spell state get out of sync
        
        for i in 0..self.bytecode.len().saturating_sub(110) {
            let section = &self.bytecode[i..std::cmp::min(i + 110, self.bytecode.len())];
            
            // Pattern: Spell execution without vault state verification
            let has_spell_call = section.windows(15).any(|w| {
                w.contains(&0xF4) && // DELEGATECALL (to spell)
                w.contains(&0x35)    // CALLDATALOAD (strategy params)
            });
            
            let no_state_verify = !section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (vault state)
                w.contains(&0x14) && // EQ (compare)
                w.contains(&0x57)    // JUMPI (revert if mismatch)
            });
            
            if has_spell_call && no_state_verify {
                vulnerabilities.push(BlueberryVulnerability::SpellVaultStateDesync {
                    description: format!("Blueberry spell-vault state desync at PC {}. Architecture: Bank (vault) holds assets, Spell contracts execute strategies via delegatecall. Risk: Spell assumes vault state X, actual state Y → incorrect calculation. Attack: 1) Vault state: 100 ETH collateral, 2) Spell executes assuming 100 ETH, 3) Meanwhile another tx removed 50 ETH, 4) Spell executes with wrong state → over-borrow or liquidation bypass. Mitigation: Atomic state lock during spell execution, verify vault state matches spell expectations before execution, state checksum validation.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
            
            // Pattern: Leverage calculation without position bounds
            let has_leverage_calc = section.windows(12).any(|w| {
                w.contains(&0x02) && // MUL (collateral * leverage)
                w.contains(&0x04) && // DIV (calculate borrow)
                w.contains(&0xF1)    // CALL (borrow)
            });
            
            let no_max_leverage = !section.windows(10).any(|w| {
                w.contains(&0x10) && // LT (vs max)
                w.contains(&0x57)    // JUMPI (revert)
            });
            
            if has_leverage_calc && no_max_leverage {
                vulnerabilities.push(BlueberryVulnerability::LeveragePositionManipulation {
                    description: format!("Leverage position manipulation at PC {}. Blueberry allows levered yield farming (e.g., 3x leverage on Curve LP). Risk: Excessive leverage → liquidation cascade. Attack: 1) Open max leverage position (10x), 2) Small price move → position liquidatable, 3) Attacker liquidates → seizes collateral + bonus. Or: Use flash loans to manipulate collateral value, borrow max, default. Mitigation: Max leverage cap (3x), gradual leverage increase, health factor monitoring, liquidation buffer (maintain 110% collateral ratio).", i),
                    location: i,
                    confidence: 0.84,
                });
            }
        }
        
        vulnerabilities
    }
}
