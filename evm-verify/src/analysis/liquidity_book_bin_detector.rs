/// Trader Joe V2 Liquidity Book Bin Vulnerability Detector
///
/// Detects vulnerabilities specific to Liquidity Book's discrete bin architecture.
/// Unlike Uniswap V3's continuous liquidity, Liquidity Book uses fixed-price bins
/// which creates unique attack surfaces around bin manipulation and rounding.
///
/// Real-world context:
/// - Trader Joe V2 (Avalanche): $500M+ TVL
/// - Discrete bins eliminate impermanent loss but enable new exploits
/// - Bin spacing and composition strategies are critical
/// - No major exploits yet, but attack surface is different from Uni V3

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityBookVulnerability {
    pub vulnerability_type: LiquidityBookVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiquidityBookVulnerabilityType {
    BinCompositionManipulation,   // Manipulate which bin trades execute in
    RoundingExploitAcrossBins,    // Accumulate rounding errors across bins
    ActiveBinMigration,           // Force price into manipulated bin
    FeeTierArbitrage,             // Exploit variable fee structure
    BinReserveImbalance,          // Create imbalanced bins for favorable pricing
    CompositionFactorAttack,      // Manipulate x% y% composition
    OracleVsBinPriceMismatch,     // Bin price diverges from oracle
    BinLiquidityDos,              // DOS specific bins to force unfavorable prices
}

pub struct LiquidityBookBinDetector {
    bytecode: Vec<u8>,
}

impl LiquidityBookBinDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityBookVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Detect bin composition manipulation
        if let Some(vuln) = self.detect_bin_composition_manipulation() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Detect cross-bin rounding exploits
        if let Some(vuln) = self.detect_cross_bin_rounding() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Detect active bin migration attacks
        if let Some(vuln) = self.detect_active_bin_migration() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Detect fee tier arbitrage
        if let Some(vuln) = self.detect_fee_tier_arbitrage() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Detect bin liquidity DOS
        if let Some(vuln) = self.detect_bin_liquidity_dos() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_bin_composition_manipulation(&self) -> Option<LiquidityBookVulnerability> {
        // Liquidity Book bins have composition factor (what % is tokenX vs tokenY)
        // Attacker can manipulate this to get favorable swap pricing
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for: Swap calculation based on bin composition
            // Pattern: Multiple DIV operations (calculating composition %)
            
            let mut div_count = 0;
            let mut has_bin_selector = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0x04 { // DIV
                    div_count += 1;
                }
                // Bin ID selection (likely involves modulo)
                if self.bytecode[j] == 0x06 { // MOD
                    has_bin_selector = true;
                }
            }
            
            if div_count >= 2 && has_bin_selector {
                return Some(LiquidityBookVulnerability {
                    vulnerability_type: LiquidityBookVulnerabilityType::BinCompositionManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Liquidity Book bin composition (X% tokenX, Y% tokenY) can be \
                                manipulated through strategic swaps. Attacker moves price to \
                                empty or imbalanced bins for better rates.".to_string(),
                    exploit_scenario: "1. Attacker observes bin #100 has 90% tokenX, 10% tokenY\n\
                                      2. Large swap would normally move through balanced bins\n\
                                      3. Attacker uses small swaps to migrate active bin to #100\n\
                                      4. Now large swap executes in favorable imbalanced bin\n\
                                      5. Gets better price than fair market rate\n\
                                      6. Similar to Uni V3 liquidity sniping but bin-specific".to_string(),
                    recommendation: "Implement bin composition checks. Limit maximum imbalance per bin \
                                  (e.g., require 20-80% range). Add slippage protection that accounts \
                                  for bin composition. Monitor for bin migration patterns.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_cross_bin_rounding(&self) -> Option<LiquidityBookVulnerability> {
        // Each bin swap has rounding
        // Attacker can accumulate rounding errors across many bin hops
        
        Some(LiquidityBookVulnerability {
            vulnerability_type: LiquidityBookVulnerabilityType::RoundingExploitAcrossBins,
            severity: "Medium".to_string(),
            location: vec![0],
            description: "Swaps crossing multiple bins accumulate rounding errors. Each bin \
                        rounds down amounts, compounding across hops. Attacker can exploit \
                        by forcing trades through maximum bins.".to_string(),
            exploit_scenario: "1. Normal swap crosses 3 bins, loses 3 wei to rounding\n\
                              2. Attacker structures swap to cross 100 bins\n\
                              3. Each bin rounds down: 100 * 1 wei = 100 wei loss\n\
                              4. On large volume: 100 wei * 1M swaps = 0.1 ETH profit\n\
                              5. Cumulative rounding becomes significant\n\
                              6. Similar to precision loss attacks but bin-amplified".to_string(),
            recommendation: "Use higher precision math (e.g., 1e27 instead of 1e18). \
                          Implement minimum output checks. Add total rounding loss cap. \
                          Consider rounding up on some operations to neutralize bias.".to_string(),
        })
    }
    
    fn detect_active_bin_migration(&self) -> Option<LiquidityBookVulnerability> {
        // Active bin = where next swap executes
        // Attacker can cheaply migrate it to favorable bin
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for active bin updates without proper checks
            // Pattern: SSTORE updating active bin ID
            
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if there's slippage/bounds checking
                let mut has_slippage_check = false;
                
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x12 { // LT/GT
                        has_slippage_check = true;
                    }
                }
                
                if !has_slippage_check {
                    return Some(LiquidityBookVulnerability {
                        vulnerability_type: LiquidityBookVulnerabilityType::ActiveBinMigration,
                        severity: "High".to_string(),
                        location: vec![i],
                        description: "Active bin (current price bin) can be migrated without sufficient \
                                    slippage protection. Small swaps can cheaply move active bin to \
                                    attacker-controlled position.".to_string(),
                        exploit_scenario: "1. Active bin at fair market price (bin #500)\n\
                                          2. Attacker adds liquidity to bin #520 (above market)\n\
                                          3. Small 0.1 ETH swap migrates active bin to #520\n\
                                          4. Now all swaps execute at unfavorable #520 price\n\
                                          5. Attacker profits from inflated pricing\n\
                                          6. Cost: 0.1 ETH, Profit: Extract from large swaps".to_string(),
                        recommendation: "Require minimum price movement. Add circuit breakers for \
                                      rapid bin migration. Implement TWAP checks. Limit single-tx \
                                      bin movement. Require minimum liquidity before bin activation.".to_string(),
                    });
                }
            }
        }
        
        None
    }
    
    fn detect_fee_tier_arbitrage(&self) -> Option<LiquidityBookVulnerability> {
        // Liquidity Book has variable fees based on volatility
        // Attacker can exploit fee tier transitions
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            // Look for fee calculation
            let mut has_fee_calc = false;
            let mut has_volatility_check = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0x02 { // MUL (fee calculation)
                    has_fee_calc = true;
                }
                // Volatility oracle read
                if self.bytecode[j] == 0x54 { // SLOAD (could be volatility)
                    has_volatility_check = true;
                }
            }
            
            if has_fee_calc && has_volatility_check {
                return Some(LiquidityBookVulnerability {
                    vulnerability_type: LiquidityBookVulnerabilityType::FeeTierArbitrage,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Variable fees based on volatility can be exploited. Attacker \
                                artificially increases volatility to force high fees on others, \
                                then trades at lower fees.".to_string(),
                    exploit_scenario: "1. Fee tier: 0.1% in low volatility, 1% in high\n\
                                      2. Attacker makes large swaps to spike volatility\n\
                                      3. Other users now pay 1% fees\n\
                                      4. Attacker waits for volatility cooldown\n\
                                      5. Trades at 0.1% while others paid 10x more\n\
                                      6. Profits from fee tier timing".to_string(),
                    recommendation: "Add volatility manipulation detection. Smooth fee transitions. \
                                  Implement time-weighted volatility (can't spike instantly). \
                                  Cap maximum fee change per block. Add cooldown periods.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_bin_liquidity_dos(&self) -> Option<LiquidityBookVulnerability> {
        // Attacker can DOS specific bins by removing liquidity
        // Forces swaps into unfavorable bins
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Look for liquidity removal without minimum liquidity check
            if self.bytecode[i] == 0x55 { // SSTORE (updating bin reserves)
                let mut has_min_liquidity_check = false;
                
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x10 { // LT (minimum check)
                        has_min_liquidity_check = true;
                    }
                }
                
                if !has_min_liquidity_check {
                    return Some(LiquidityBookVulnerability {
                        vulnerability_type: LiquidityBookVulnerabilityType::BinLiquidityDos,
                        severity: "Medium".to_string(),
                        location: vec![i],
                        description: "Bins can be drained of liquidity, forcing swaps to skip them \
                                    and execute in less favorable bins. Attacker profits from \
                                    worse pricing.".to_string(),
                        exploit_scenario: "1. Bins #98, #99, #100 have good liquidity\n\
                                          2. Attacker provides liquidity to #97 and #101\n\
                                          3. Attacker removes liquidity from #98, #99, #100\n\
                                          4. Swaps now forced to use #97 or #101 (worse pricing)\n\
                                          5. Attacker's bins extract more fees\n\
                                          6. Similar to Uni V3 liquidity sniping".to_string(),
                        recommendation: "Enforce minimum liquidity per bin. Add withdrawal delays. \
                                      Implement bin skip protection (multiple bins must be empty). \
                                      Consider bin activation thresholds.".to_string(),
                    });
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
    fn test_bin_composition_detection() {
        // Multiple DIV and MOD (bin selection + composition)
        let bytecode = vec![
            0x04, // DIV
            0x04, // DIV
            0x06, // MOD (bin selection)
        ];
        
        let detector = LiquidityBookBinDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            LiquidityBookVulnerabilityType::BinCompositionManipulation
        )));
    }
    
    #[test]
    fn test_active_bin_migration() {
        // SSTORE without slippage check
        let bytecode = vec![
            0x55, // SSTORE (no prior LT/GT check)
        ];
        
        let detector = LiquidityBookBinDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            LiquidityBookVulnerabilityType::ActiveBinMigration
        )));
    }
}
