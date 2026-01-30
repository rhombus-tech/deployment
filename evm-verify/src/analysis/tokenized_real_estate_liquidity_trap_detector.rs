// Tokenized Real Estate Liquidity Trap Detector
// Detects illiquid redemption and forced sale discount vulnerabilities

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizedRealEstateLiquidityVulnerability {
    pub location: usize,
    pub vulnerability_type: RealEstateLiquidityType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RealEstateLiquidityType {
    IlliquidRedemption,              // Cannot redeem due to lack of liquidity
    ForcedSaleDiscount,              // Redemption at steep discount
    RedemptionQueueGriefing,         // Queue manipulation prevents redemption
    PropertyValuationLag,            // Stale property valuations
    EmergencyLiquidationRisk,        // Forced liquidation at unfavorable terms
    SecondaryMarketAbsence,          // No secondary market for trading
}

pub struct TokenizedRealEstateLiquidityDetector {
    bytecode: Vec<u8>,
}

impl TokenizedRealEstateLiquidityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TokenizedRealEstateLiquidityVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_illiquid_redemption() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::IlliquidRedemption,
                severity: "Critical".to_string(),
                description: "Redemption mechanism lacks liquidity buffer. Users cannot exit positions \
                             when underlying real estate is illiquid.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_forced_sale_discount() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::ForcedSaleDiscount,
                severity: "High".to_string(),
                description: "Redemption price calculated without discount protection. Users forced \
                             to accept steep discounts during low liquidity periods.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_redemption_queue_griefing() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::RedemptionQueueGriefing,
                severity: "High".to_string(),
                description: "Redemption queue vulnerable to front-running and griefing. Large \
                             redemptions can block smaller users indefinitely.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_property_valuation_lag() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::PropertyValuationLag,
                severity: "Medium".to_string(),
                description: "Property valuations updated infrequently. Redemption prices based on \
                             outdated assessments enabling arbitrage.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_emergency_liquidation_risk() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::EmergencyLiquidationRisk,
                severity: "Critical".to_string(),
                description: "Emergency liquidation lacks minimum price protection. Properties can \
                             be liquidated at fire-sale prices harming token holders.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_secondary_market_absence() {
            vulnerabilities.push(TokenizedRealEstateLiquidityVulnerability {
                location: loc,
                vulnerability_type: RealEstateLiquidityType::SecondaryMarketAbsence,
                severity: "Medium".to_string(),
                description: "No secondary market integration for price discovery. Users forced to \
                             use primary redemption at potentially unfavorable rates.".to_string(),
                confidence: 0.79,
            });
        }

        vulnerabilities
    }

    fn detect_illiquid_redemption(&self) -> Option<usize> {
        // Pattern: Redemption without liquidity reserve check
        // Transfer out without verifying available liquid funds
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (transfer for redemption)
                let mut is_redemption = false;
                let mut checks_liquidity = false;
                
                // Check if redemption (caller receiving funds)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x33 {  // CALLER
                        is_redemption = true;
                    }
                }
                
                // Check for liquidity buffer verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (available liquidity)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (sufficient liquidity)
                                checks_liquidity = true;
                            }
                        }
                    }
                }
                
                if is_redemption && !checks_liquidity {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_forced_sale_discount(&self) -> Option<usize> {
        // Pattern: Redemption price without minimum floor
        // Price calculation without discount protection
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 {  // MUL (calculate redemption amount)
                let mut is_redemption_calc = false;
                let mut has_minimum_price = false;
                
                // Check if redemption calculation (followed by transfer)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 {  // CALL (execute redemption)
                        is_redemption_calc = true;
                    }
                }
                
                // Check for minimum price floor
                for j in (i.saturating_sub(20))..i {
                    // Maximum comparison to enforce floor
                    if self.bytecode[j] == 0x11 {  // GT (price > minimum)
                        has_minimum_price = true;
                    }
                }
                
                if is_redemption_calc && !has_minimum_price {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_redemption_queue_griefing(&self) -> Option<usize> {
        // Pattern: Queue processing without anti-griefing measures
        // FIFO queue without size limits or priority
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (add to redemption queue)
                let mut is_queue_addition = false;
                let mut has_size_limit = false;
                
                // Check if queue operation (incrementing queue pointer)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x01 {  // ADD (increment index)
                        is_queue_addition = true;
                    }
                }
                
                // Check for queue size limit
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (queue size)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (under maximum)
                                has_size_limit = true;
                            }
                        }
                    }
                }
                
                if is_queue_addition && !has_size_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_property_valuation_lag(&self) -> Option<usize> {
        // Pattern: Valuation timestamp not checked for freshness
        // Using property value without age verification
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (property valuation)
                let mut used_for_pricing = false;
                let mut checks_age = false;
                
                // Check if used in pricing
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV
                        used_for_pricing = true;
                    }
                }
                
                // Check for age verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (calculate age)
                                for m in k+1..(k+5).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x10 {  // LT (not too old)
                                        checks_age = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if used_for_pricing && !checks_age {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_emergency_liquidation_risk(&self) -> Option<usize> {
        // Pattern: Liquidation without minimum price protection
        // Emergency sale execution without reserve price
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (execute sale)
                let mut is_liquidation = false;
                let mut has_reserve_price = false;
                
                // Check if liquidation (emergency flag check)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (emergency mode)
                        is_liquidation = true;
                    }
                }
                
                // Check for reserve price enforcement
                for j in (i.saturating_sub(20))..i {
                    // Price must exceed minimum
                    if self.bytecode[j] == 0x10 {  // LT (price check)
                        for k in (j.saturating_sub(10))..j {
                            if self.bytecode[k] == 0x60 || self.bytecode[k] == 0x61 {  // PUSH (reserve)
                                has_reserve_price = true;
                            }
                        }
                    }
                }
                
                if is_liquidation && !has_reserve_price {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_secondary_market_absence(&self) -> Option<usize> {
        // Pattern: No external price feed integration
        // Redemption uses only internal pricing without market reference
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 {  // MUL (calculate redemption)
                let mut is_redemption_pricing = false;
                let mut has_market_price = false;
                
                // Check if redemption pricing
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 {  // CALL (redeem)
                        is_redemption_pricing = true;
                    }
                }
                
                // Check for external market price (STATICCALL to DEX/oracle)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (market price)
                        has_market_price = true;
                    }
                }
                
                if is_redemption_pricing && !has_market_price {
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
    fn test_illiquid_redemption() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL (redeem without liquidity check)
        ];
        
        let detector = TokenizedRealEstateLiquidityDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RealEstateLiquidityType::IlliquidRedemption)));
    }

    #[test]
    fn test_forced_sale_discount() {
        let bytecode = vec![
            0x60, 0x0A, // PUSH1 10
            0x02, // MUL (calculate redemption without minimum)
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL (execute at any price)
        ];
        
        let detector = TokenizedRealEstateLiquidityDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RealEstateLiquidityType::ForcedSaleDiscount)));
    }
}
