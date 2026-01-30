use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegulatoryArbitrageVulnerability {
    SanctionEvasion { description: String, location: usize, confidence: f32 },
    JurisdictionExploitation { description: String, location: usize, confidence: f32 },
}

pub struct RegulatoryArbitrageDetector {
    bytecode: Vec<u8>,
}

impl RegulatoryArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RegulatoryArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Regulatory arbitrage: Exploiting jurisdiction differences, evading sanctions/compliance
        
        for i in 0..self.bytecode.len().saturating_sub(75) {
            let section = &self.bytecode[i..std::cmp::min(i + 75, self.bytecode.len())];
            
            // Pattern 1: No address blacklist/whitelist (sanctions compliance)
            let has_transfer = section.windows(10).any(|w| {
                w.contains(&0xF1) && // CALL (transfer)
                w.contains(&0x35)    // CALLDATALOAD (to address)
            });
            
            let no_sanctions_check = !section.windows(15).any(|w| {
                w.contains(&0x33) && // CALLER
                w.contains(&0x54) && // SLOAD (blacklist)
                w.contains(&0x14) && // EQ (check)
                w.contains(&0x57)    // JUMPI (block)
            });
            
            if has_transfer && no_sanctions_check {
                vulnerabilities.push(RegulatoryArbitrageVulnerability::SanctionEvasion {
                    description: format!("Sanction evasion at PC {}. No checks for sanctioned addresses (OFAC, EU, UN). Risk: 1) North Korean hackers use protocol → protocol liable for facilitating. 2) Tornado Cash users route through protocol → protocol becomes mixer. 3) Russian oligarchs use protocol to evade sanctions → legal consequences. Real: OFAC sanctioned Tornado Cash addresses, all protocols interacting with them at risk. Protocols face: 1) Legal liability ($1B+ fines), 2) Delisting from exchanges, 3) Bank account closure, 4) Criminal charges for team. Mitigation: Check addresses against Chainalysis oracle, implement freezing (USDC-style), or declare protocol permissionless + jurisdiction where that's legal. Cannot fix on-chain (censorship resistance) but team's jurisdiction matters.", i),
                    location: i,
                    confidence: 0.88,
                });
            }
            
            // Pattern 2: No KYC/AML for high-value transactions
            let has_large_value_tx = section.windows(15).any(|w| {
                w.contains(&0x35) && // CALLDATALOAD (amount)
                w.contains(&0x02) && // MUL (convert to USD)
                w.contains(&0x10)    // LT (check threshold)
            });
            
            if has_large_value_tx {
                vulnerabilities.push(RegulatoryArbitrageVulnerability::JurisdictionExploitation {
                    description: format!("Jurisdiction exploitation at PC {}. Large value transfers without KYC/AML. Regulatory arbitrage: 1) Team in US (strict AML) but protocol deployed permissionlessly → gray area. 2) Users in restricted jurisdictions (US, China) access protocol → protocol violates local laws. 3) Protocol facilitates >$10k transfers without KYC → violates FinCEN rules. 4) Securities offered without registration → SEC violation. Real cases: BitMEX founders arrested, Binance $4B fine, FTX shut down. Risk: Team members criminally liable even if protocol is 'permissionless'. Mitigation: 1) Register as MSB (money service business), 2) Implement KYC for >$10k, 3) Geoblock restricted jurisdictions, 4) Token structure that's not a security, 5) Deploy truly anonymously (risky). Note: 'Code is law' doesn't protect against real law.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
