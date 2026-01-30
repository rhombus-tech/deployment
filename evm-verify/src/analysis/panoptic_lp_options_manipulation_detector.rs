// Panoptic LP Options Manipulation Detector
// Detects manipulation in Uniswap v3 LP position options (perpetual options)

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanopticVulnerability {
    pub location: usize,
    pub vulnerability_type: PanopticVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PanopticVulnerabilityType {
    PositionSizingManipulation,     // Manipulate LP position size calculation
    PriceRangeExploit,              // Exploit tick range boundaries
    StreamiaAccumulationGaming,     // Game premia accumulation mechanism
    LiquidationThresholdBypass,     // Bypass liquidation checks
    FeeTierArbitrage,               // Arbitrage between fee tiers
    TickManipulationAttack,         // Manipulate tick observations
}

pub struct PanopticDetector {
    bytecode: Vec<u8>,
}

impl PanopticDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PanopticVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_position_sizing() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::PositionSizingManipulation,
                severity: SecuritySeverity::High,
                description: "LP position size calculated from single-block liquidity. Flash loans \
                             can manipulate size calculation affecting option valuation.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_price_range_exploit() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::PriceRangeExploit,
                severity: SecuritySeverity::Critical,
                description: "Tick range boundaries not validated. Position can be created at extreme \
                             ticks causing overflow in premia calculations.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_streamia_gaming() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::StreamiaAccumulationGaming,
                severity: SecuritySeverity::High,
                description: "Premia accumulation uses block-level snapshots. Attacker can manipulate \
                             timing of position updates to maximize collected premia unfairly.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_liquidation_bypass() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::LiquidationThresholdBypass,
                severity: SecuritySeverity::Critical,
                description: "Liquidation threshold check uses stale data. Position can become \
                             undercollateralized before liquidation triggers.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_fee_tier_arbitrage() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::FeeTierArbitrage,
                severity: SecuritySeverity::Medium,
                description: "Fee tier selection not validated. Arbitrageur can exploit pricing \
                             differences between fee tiers for same underlying.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_tick_manipulation() {
            vulnerabilities.push(PanopticVulnerability {
                location: loc,
                vulnerability_type: PanopticVulnerabilityType::TickManipulationAttack,
                severity: SecuritySeverity::High,
                description: "Tick observation uses single sample. Large swap can manipulate tick to \
                             affect option valuation and force liquidations.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_position_sizing(&self) -> Option<usize> {
        // Pattern: Liquidity query without time-weighted averaging
        // STATICCALL (pool.liquidity) → use without multiple samples
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (get liquidity)
                let mut has_twap = false;
                
                // Check for multiple liquidity samples
                let mut call_count = 1;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {
                        call_count += 1;
                    }
                }
                
                if call_count >= 2 {
                    has_twap = true;
                }
                
                // Single sample used for sizing
                if !has_twap {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV (calc size)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_price_range_exploit(&self) -> Option<usize> {
        // Pattern: Tick range without bounds validation
        // Tick values used without checking against MIN_TICK/MAX_TICK
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for tick parameter loading
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (tick)
                let mut has_bounds_check = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Bounds validation: compare against limits
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        // Check if comparing against constant (tick limits)
                        for k in (j.saturating_sub(5))..j {
                            if matches!(self.bytecode[k], 0x62..=0x63) {  // PUSH3+ (large constant)
                                has_bounds_check = true;
                            }
                        }
                    }
                    
                    // Tick used in calculation without validation
                    if !has_bounds_check && (self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_streamia_gaming(&self) -> Option<usize> {
        // Pattern: Premia update without time-weighting
        // Premia calculation using single block timestamp
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x42 {  // TIMESTAMP
                let mut has_time_weighting = false;
                
                // Check for time delta calculation (TWAP-like)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x03 {  // SUB (time delta)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x04 {  // DIV (average)
                                has_time_weighting = true;
                            }
                        }
                    }
                }
                
                // Premia updated without time-weighting
                if !has_time_weighting {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (premia)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_liquidation_bypass(&self) -> Option<usize> {
        // Pattern: Liquidation check using cached data
        // Collateral check without fresh oracle call
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for liquidation trigger
            if self.bytecode[i] == 0x10 {  // LT (collateral < threshold)
                let mut uses_fresh_data = false;
                
                // Check if oracle called before comparison
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (fresh price)
                        uses_fresh_data = true;
                    }
                }
                
                // Check if this leads to liquidation
                let mut is_liquidation = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 {  // JUMPI (liquidate)
                        is_liquidation = true;
                    }
                }
                
                if is_liquidation && !uses_fresh_data {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_fee_tier_arbitrage(&self) -> Option<usize> {
        // Pattern: Fee tier not validated against expected
        // Pool address used without fee tier verification
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (pool address)
                let mut validates_fee_tier = false;
                
                // Check for fee tier validation
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Fee validation: STATICCALL to get fee, then compare
                    if self.bytecode[j] == 0xFA {
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (check fee)
                                validates_fee_tier = true;
                            }
                        }
                    }
                }
                
                // Pool used without fee validation
                if !validates_fee_tier {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xF1 {  // CALL (use pool)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_tick_manipulation(&self) -> Option<usize> {
        // Pattern: Single tick observation for valuation
        // Tick read once without TWAP
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (observe)
                let mut observation_count = 1;
                
                // Count observations
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {
                        observation_count += 1;
                    }
                }
                
                // Single observation used for valuation
                if observation_count == 1 {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x04 {  // MUL/DIV (value)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::Panoptic,
                severity: v.severity,
                description: format!(
                    "Panoptic {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_sizing_manipulation() {
        let bytecode = vec![
            0xFA, // STATICCALL (get liquidity)
            0x60, 0x64, // PUSH1 100
            0x02, // MUL (calculate size - single sample)
        ];
        
        let detector = PanopticDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PanopticVulnerabilityType::PositionSizingManipulation)));
    }

    #[test]
    fn test_tick_manipulation() {
        let bytecode = vec![
            0xFA, // STATICCALL (observe once)
            0x60, 0x00, // PUSH1 0
            0x04, // DIV (value from single tick)
        ];
        
        let detector = PanopticDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PanopticVulnerabilityType::TickManipulationAttack)));
    }
}
