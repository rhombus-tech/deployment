/// Yield Tokenization (Principal/Yield Token) Vulnerability Analyzer
/// Targets: Pendle, Element Finance, Spectra, Sense Finance
/// Market: $2B+ TVL with complex time-decay mechanics

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldTokenizationVulnerability {
    pub vulnerability_type: YieldTokenVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum YieldTokenVulnType {
    /// PT/YT pricing oracle manipulation
    PrincipalYieldPriceManipulation,
    /// Maturity date exploit (time-based gaming)
    MaturityDateExploit,
    /// Yield stripping attack
    YieldStrippingAttack,
    /// Redemption timing manipulation
    RedemptionTimingManipulation,
    /// AMM curve gaming for time-decaying assets
    TimeDecayAMMGaming,
    /// Implied yield calculation error
    ImpliedYieldCalculationError,
    /// Flash loan PT/YT arbitrage
    FlashLoanPTYTArbitrage,
    /// Pre-maturity withdrawal exploit
    PreMaturityWithdrawalExploit,
}

pub struct YieldTokenizationAnalyzer {
    bytecode: Vec<u8>,
}

impl YieldTokenizationAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_yield_tokenization_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_price_manipulation());
        vulnerabilities.extend(self.detect_maturity_exploit());
        vulnerabilities.extend(self.detect_yield_stripping());
        vulnerabilities.extend(self.detect_redemption_timing());
        vulnerabilities.extend(self.detect_amm_curve_gaming());
        vulnerabilities.extend(self.detect_implied_yield_errors());
        vulnerabilities.extend(self.detect_flash_loan_arbitrage());

        vulnerabilities
    }

    fn is_yield_tokenization_contract(&self) -> bool {
        let yield_signatures = [
            &[0x3d, 0x18, 0xb9, 0x12][..], // splitYield() / mintPrincipalAndYield()
            &[0xbd, 0x02, 0xd0, 0xf5][..], // redeemPrincipal()
            &[0x70, 0xa0, 0x82, 0x31][..], // maturityDate()
            &[0xe4, 0x15, 0x0d, 0x04][..], // getImpliedRate()
        ];

        yield_signatures.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        }) && self.bytecode.len() > 3000
    }

    fn detect_price_manipulation(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.bytecode[i] == 0x04 { // DIV (price calculation)
                let uses_spot_price = self.bytecode[i.saturating_sub(50)..i]
                    .windows(1).any(|w| w[0] == 0xFA); // STATICCALL to AMM

                let no_twap = !self.bytecode[i.saturating_sub(100)..i+50]
                    .windows(1).any(|w| w[0] == 0x42); // No TIMESTAMP averaging

                if uses_spot_price && no_twap {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::PrincipalYieldPriceManipulation,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "PT/YT price uses spot AMM price without TWAP protection".to_string(),
                        exploit_scenario: "Principal Token Price Manipulation:\n\
                            1. Pendle PT-stETH trades at 0.95 ETH (5% discount to maturity)\n\
                            2. Protocol uses Pendle AMM spot price for valuation\n\
                            3. Attacker flash loans 50,000 ETH\n\
                            4. Buys massive PT, pushing price to 0.98 ETH\n\
                            5. Protocol values collateral at manipulated price\n\
                            6. Attacker borrows against inflated collateral\n\
                            7. Sells PT back, price corrects to 0.95\n\
                            8. Protocol left with undercollateralized loans\n\
                            \n\
                            Real risk: Time-decaying assets highly manipulable".to_string(),
                        remediation: "Secure PT/YT pricing:\n\
                            1. Use time-weighted average price (30+ minute TWAP)\n\
                            2. Multiple price sources (Pendle + Curve + Uniswap)\n\
                            3. Price deviation bounds checking\n\
                            4. Decay price toward par as maturity approaches\n\
                            5. Consider implied yield vs market yield validation".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_maturity_exploit(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (maturity check)
                let maturity_check = self.bytecode[i+1..i+30]
                    .windows(2).any(|w| w[0] == 0x11 || w[0] == 0x10); // GT or LT

                let affects_redemption = self.bytecode[i+1..i+80]
                    .windows(1).any(|w| w[0] == 0xF1); // CALL (token transfer)

                // Critical: Time manipulation possible
                if maturity_check && affects_redemption {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::MaturityDateExploit,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Maturity date check vulnerable to timestamp manipulation".to_string(),
                        exploit_scenario: "Maturity Timestamp Gaming:\n\
                            1. PT-stETH matures at timestamp 1735689600 (Jan 1, 2025)\n\
                            2. Current time: 1735689590 (10 seconds before maturity)\n\
                            3. PT trades at 0.999 ETH (almost at par)\n\
                            4. Miner/validator manipulates timestamp forward +15 seconds\n\
                            5. Contract sees maturity reached early\n\
                            6. Allows redemption at 1.0 ETH before actual maturity\n\
                            7. Arbitrageurs profit from early redemption\n\
                            \n\
                            Lower severity but possible on L2s with flexible timestamps".to_string(),
                        remediation: "Secure maturity checks:\n\
                            1. Use block number + average block time instead of timestamp\n\
                            2. Add safety margin (e.g., +1 hour after stated maturity)\n\
                            3. Gradual transition to redemption (not instant)\n\
                            4. Monitor for timestamp anomalies\n\
                            5. Consider multiple maturity windows".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_yield_stripping(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.bytecode[i] == 0x03 { // SUB (yield calculation)
                let calculates_accrued = self.bytecode[i.saturating_sub(40)..i]
                    .windows(1).filter(|w| w[0] == 0x54).count() >= 2; // Multiple SLOADs

                let no_minimum_check = !self.bytecode[i+1..i+50]
                    .windows(2).any(|w| w[0] == 0x11 && w[1] == 0x57); // No GT check

                if calculates_accrued && no_minimum_check {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::YieldStrippingAttack,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Yield accrual calculation allows negative yield extraction".to_string(),
                        exploit_scenario: "Yield Stripping Attack:\n\
                            1. User holds PT-stETH (principal) + YT-stETH (yield)\n\
                            2. stETH rebase generates 1 stETH yield\n\
                            3. User claims yield through YT\n\
                            4. Due to rounding, claims 1.001 stETH\n\
                            5. PT value should decrease by 1.001, but only decreases 1.0\n\
                            6. User extracted 0.001 stETH from principal holders\n\
                            7. Repeated attacks drain principal value\n\
                            \n\
                            Impact: PT holders lose value to YT holders".to_string(),
                        remediation: "Prevent yield stripping:\n\
                            1. Atomic yield+principal accounting\n\
                            2. Track total yield distributed strictly\n\
                            3. Ensure PT + YT always equals underlying\n\
                            4. Add rounding in favor of PT holders\n\
                            5. Regular reconciliation of PT/YT supply vs underlying".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_redemption_timing(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x55 { // SSTORE (redemption state)
                let follows_maturity = self.bytecode[i.saturating_sub(30)..i]
                    .windows(1).any(|w| w[0] == 0x42); // TIMESTAMP

                let no_cooldown = !self.bytecode[i.saturating_sub(50)..i]
                    .windows(2).any(|w| w[0] == 0x01 && w[1] == 0x42); // ADD + TIMESTAMP (delay)

                if follows_maturity && no_cooldown {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::RedemptionTimingManipulation,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Redemption allowed immediately at maturity without cooldown".to_string(),
                        exploit_scenario: "Redemption Front-Running:\n\
                            1. PT-stETH matures at block N\n\
                            2. No cooldown period for redemptions\n\
                            3. Last stETH rebase before maturity: +2% (positive)\n\
                            4. Attacker sees maturity block approaching\n\
                            5. Buys PT at 0.98 ETH in block N-1\n\
                            6. Redeems at 1.0 ETH in block N\n\
                            7. Profits from final rebase without holding risk\n\
                            8. Regular PT holders diluted\n\
                            \n\
                            Impact: Final yield extracted by front-runners".to_string(),
                        remediation: "Add redemption cooldown:\n\
                            1. Minimum holding period before redemption (1-7 days)\n\
                            2. Gradual redemption window (not instant)\n\
                            3. Pro-rata distribution for simultaneous redeemers\n\
                            4. Redemption queue to prevent front-running\n\
                            5. Consider Dutch auction for final yield distribution".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_amm_curve_gaming(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.bytecode[i] == 0x0A { // EXP (exponential for time decay curve)
                let time_based = self.bytecode[i.saturating_sub(30)..i]
                    .windows(1).any(|w| w[0] == 0x42); // TIMESTAMP

                let no_bounds = !self.bytecode[i+1..i+50]
                    .windows(2).any(|w| w[0] == 0x11 && w[1] == 0x57); // GT bound check

                if time_based && no_bounds {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::TimeDecayAMMGaming,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Time-decay AMM curve parameters not bounded allowing gaming".to_string(),
                        exploit_scenario: "AMM Curve Gaming Attack:\n\
                            1. Pendle AMM uses time-decay curve for PT pricing\n\
                            2. Curve steepens as maturity approaches\n\
                            3. No bounds on curve steepness parameter\n\
                            4. Attacker manipulates time-to-maturity perception\n\
                            5. Causes AMM to misprice PT (too steep curve)\n\
                            6. Arbitrages against misprice\n\
                            7. AMM LPs lose value to arbitrageur\n\
                            \n\
                            Or: Attacker exploits natural curve steepening near maturity\n\
                            for outsized profits during high volatility".to_string(),
                        remediation: "Secure AMM curve:\n\
                            1. Bound maximum curve steepness\n\
                            2. Use battle-tested curve formulas (Pendle V2)\n\
                            3. Gradual curve adjustments (no jumps)\n\
                            4. Circuit breakers for extreme curvature\n\
                            5. Monitor for unusual arbitrage activity".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_implied_yield_errors(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x04 && self.bytecode.get(i+5) == Some(&0x03) { // DIV then SUB (yield calc)
                let no_overflow_check = !self.bytecode[i.saturating_sub(20)..i]
                    .windows(2).any(|w| w[0] == 0x11 && w[1] == 0x15); // GT + ISZERO

                if no_overflow_check {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::ImpliedYieldCalculationError,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Implied yield calculation without overflow protection".to_string(),
                        exploit_scenario: "Implied Yield Calculation Overflow:\n\
                            1. Protocol calculates implied yield: (1 - PT_price) / time_to_maturity\n\
                            2. If PT price > 1 (trading above par), calculation underflows\n\
                            3. Or if time_to_maturity very small, division overflows\n\
                            4. Implied yield shows as negative or massive positive\n\
                            5. Dependent systems use wrong yield for pricing\n\
                            6. Cascading pricing errors across protocols\n\
                            \n\
                            Edge case but breaks assumptions of yield-dependent systems".to_string(),
                        remediation: "Safe yield calculations:\n\
                            1. Check PT price < 1 before calculating discount\n\
                            2. Handle edge cases (matured, PT > 1)\n\
                            3. Use safe math libraries\n\
                            4. Cap maximum implied yield at reasonable bound\n\
                            5. Return error instead of wrapping on overflow".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_flash_loan_arbitrage(&self) -> Vec<YieldTokenizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.bytecode[i] == 0x02 { // MUL (calculating split amounts)
                let has_split_logic = self.bytecode[i+1..i+100]
                    .windows(1).filter(|w| w[0] == 0xF1).count() >= 2; // Multiple transfers (PT+YT)

                let no_lock = !self.bytecode[i.saturating_sub(80)..i+80]
                    .windows(1).any(|w| w[0] == 0x42); // No timestamp lock

                if has_split_logic && no_lock {
                    vulnerabilities.push(YieldTokenizationVulnerability {
                        vulnerability_type: YieldTokenVulnType::FlashLoanPTYTArbitrage,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "PT/YT splitting allows flash loan arbitrage without cooldown".to_string(),
                        exploit_scenario: "Flash Loan PT/YT Arbitrage:\n\
                            1. PT trading at 0.95 ETH, YT at 0.06 ETH (total 1.01 ETH)\n\
                            2. Underlying stETH at 1.00 ETH\n\
                            3. Arbitrage opportunity: split stETH → PT+YT for profit\n\
                            4. Attacker flash loans 10,000 stETH\n\
                            5. Splits into 10,000 PT + 10,000 YT\n\
                            6. Sells both: (10,000 * 0.95) + (10,000 * 0.06) = 10,100 ETH\n\
                            7. Repays 10,000 stETH loan\n\
                            8. Profits 100 ETH from price inefficiency\n\
                            9. Repeatable until prices converge\n\
                            \n\
                            Impact: Legitimate holders diluted by flash arbitrage".to_string(),
                        remediation: "Prevent flash loan arbitrage:\n\
                            1. Minimum holding period before splitting (1 block)\n\
                            2. Add small fee for split operation\n\
                            3. Rate limit splits per address\n\
                            4. Ensure PT + YT price tracks underlying closely\n\
                            5. Monitor for flash loan patterns".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_price_manipulation() {
        let bytecode = vec![
            0xFA, // STATICCALL (get AMM price)
            0x04, // DIV (calculate price)
            // No TWAP
        ];
        
        let analyzer = YieldTokenizationAnalyzer::new(bytecode);
        let vulns = analyzer.detect_price_manipulation();
        
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].vulnerability_type, YieldTokenVulnType::PrincipalYieldPriceManipulation);
    }
}
