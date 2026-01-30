// Commodity-Backed Token Arbitrage Detector
// Detects physical vs token pricing arbitrage and delivery timing exploits

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommodityBackedTokenVulnerability {
    pub location: usize,
    pub vulnerability_type: CommodityArbitrageType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommodityArbitrageType {
    PhysicalVsTokenPricing,          // Divergence between physical and token price
    StorageCostArbitrage,            // Exploit storage cost differentials
    DeliveryTimingExploit,           // Manipulate delivery timing
    QualityGradeManipulation,        // Exploit grade specification mismatches
    LocationBasisArbitrage,          // Geographic price differential exploitation
    ContangoBackwardationExploit,    // Futures curve manipulation
}

pub struct CommodityBackedTokenDetector {
    bytecode: Vec<u8>,
}

impl CommodityBackedTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CommodityBackedTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_physical_vs_token_pricing() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::PhysicalVsTokenPricing,
                severity: "High".to_string(),
                description: "Token price not anchored to physical commodity spot price. Arbitrage \
                             opportunities exist between token and physical markets.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_storage_cost_arbitrage() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::StorageCostArbitrage,
                severity: "Medium".to_string(),
                description: "Storage costs not reflected in token pricing. Holders can avoid \
                             storage fees by holding tokens instead of physical commodity.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_delivery_timing_exploit() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::DeliveryTimingExploit,
                severity: "High".to_string(),
                description: "Delivery timing manipulable by token holders. Can time delivery to \
                             coincide with favorable market conditions for arbitrage.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_quality_grade_manipulation() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::QualityGradeManipulation,
                severity: "High".to_string(),
                description: "Commodity grade specification not enforced in redemption. Inferior \
                             grade commodity can be delivered at premium grade token price.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_location_basis_arbitrage() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::LocationBasisArbitrage,
                severity: "Medium".to_string(),
                description: "Delivery location not fixed at token issuance. Geographic price \
                             differentials exploitable through strategic delivery location choice.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_contango_backwardation_exploit() {
            vulnerabilities.push(CommodityBackedTokenVulnerability {
                location: loc,
                vulnerability_type: CommodityArbitrageType::ContangoBackwardationExploit,
                severity: "High".to_string(),
                description: "Token pricing ignores futures curve structure. Can exploit contango or \
                             backwardation through strategic timing of token minting/redemption.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_physical_vs_token_pricing(&self) -> Option<usize> {
        // Pattern: Token price without physical commodity reference
        // Internal pricing without external spot price oracle
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (token price)
                let mut used_in_exchange = false;
                let mut references_spot = false;
                
                // Check if price used in mint/redeem
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV (exchange rate)
                        used_in_exchange = true;
                    }
                }
                
                // Check for physical spot price reference (oracle call)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (spot price oracle)
                        references_spot = true;
                    }
                }
                
                if used_in_exchange && !references_spot {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_storage_cost_arbitrage(&self) -> Option<usize> {
        // Pattern: Token valuation without storage fee accrual
        // Time-based value adjustment missing
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (commodity value)
                let mut used_for_redemption = false;
                let mut includes_storage_cost = false;
                
                // Check if used in redemption calculation
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 {  // CALL (redeem)
                        used_for_redemption = true;
                    }
                }
                
                // Check for storage cost calculation (time-based fee)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (time held)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x02 {  // MUL (storage fee)
                                        includes_storage_cost = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if used_for_redemption && !includes_storage_cost {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_delivery_timing_exploit(&self) -> Option<usize> {
        // Pattern: Redemption without delivery timing restrictions
        // Immediate delivery request allowed without delay
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (initiate redemption)
                let mut is_redemption = false;
                let mut has_delay_requirement = false;
                
                // Check if redemption initiation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_redemption = true;
                    }
                }
                
                // Check for minimum notice period
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (future delivery date)
                                has_delay_requirement = true;
                            }
                        }
                    }
                }
                
                if is_redemption && !has_delay_requirement {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_quality_grade_manipulation(&self) -> Option<usize> {
        // Pattern: Redemption without grade specification verification
        // No quality standard enforcement
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (delivery execution)
                let mut is_delivery = false;
                let mut verifies_grade = false;
                
                // Check if commodity delivery
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (delivery params)
                        is_delivery = true;
                    }
                }
                
                // Check for grade specification verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (grade standard)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify matches)
                                verifies_grade = true;
                            }
                        }
                    }
                }
                
                if is_delivery && !verifies_grade {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_location_basis_arbitrage(&self) -> Option<usize> {
        // Pattern: Delivery location not locked at token creation
        // Location selection allowed at redemption
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set delivery params)
                let mut sets_location = false;
                let mut location_locked = false;
                
                // Check if setting delivery location
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (location)
                        sets_location = true;
                    }
                }
                
                // Check if location was locked at minting
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (locked location)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (not set)
                                location_locked = false;
                            } else if self.bytecode[k] == 0x14 {  // EQ (must match)
                                location_locked = true;
                            }
                        }
                    }
                }
                
                if sets_location && !location_locked {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_contango_backwardation_exploit(&self) -> Option<usize> {
        // Pattern: Token pricing without futures curve consideration
        // Single spot price without term structure
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 {  // MUL (calculate token value)
                let mut is_valuation = false;
                let mut considers_term = false;
                
                // Check if token valuation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (base price)
                        is_valuation = true;
                    }
                }
                
                // Check for term structure adjustment (time-based pricing)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Check if time affects pricing
                            if self.bytecode[k] == 0x03 {  // SUB (time to maturity)
                                for m in k+1..(k+8).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x02 {  // MUL (term adjustment)
                                        considers_term = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if is_valuation && !considers_term {
                    return Some(i);
                }
            }
        }
        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_physical_vs_token_pricing() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x54, // SLOAD (internal price only)
            0x60, 0x0A, // PUSH1 10
            0x02, // MUL (exchange without spot reference)
        ];
        
        let detector = CommodityBackedTokenDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CommodityArbitrageType::PhysicalVsTokenPricing)));
    }

    #[test]
    fn test_quality_grade_manipulation() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x35, // CALLDATALOAD (delivery)
            0xF1, // CALL (deliver without grade verification)
        ];
        
        let detector = CommodityBackedTokenDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, CommodityArbitrageType::QualityGradeManipulation)));
    }
}
