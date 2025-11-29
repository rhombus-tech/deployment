/// Points & Loyalty System Gaming Detector
/// Targets: Blast, EigenLayer, Blur, Friend.tech, all points-based protocols
/// Market: 100+ protocols with billions in implied value

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointsGamingVulnerability {
    pub vulnerability_type: PointsGamingType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PointsGamingType {
    /// Sybil farming with multiple wallets
    SybilFarming,
    /// Circular farming loops
    CircularFarming,
    /// Referral system manipulation
    ReferralManipulation,
    /// Wash trading for activity points
    WashTrading,
    /// Timestamp gaming for multipliers
    TimestampGaming,
    /// Cross-protocol point arbitrage
    CrossProtocolArbitrage,
    /// Flash loan point farming
    FlashLoanFarming,
    /// Bot detection bypass
    BotDetectionBypass,
    /// Point decay exploitation
    PointDecayExploit,
    /// Tier system gaming
    TierSystemGaming,
}

pub struct PointsGamingDetector {
    bytecode: Vec<u8>,
}

impl PointsGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only analyze if contract appears to be points-related
        if !self.is_points_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_sybil_farming());
        vulnerabilities.extend(self.detect_circular_farming());
        vulnerabilities.extend(self.detect_referral_manipulation());
        vulnerabilities.extend(self.detect_wash_trading());
        vulnerabilities.extend(self.detect_timestamp_gaming());
        vulnerabilities.extend(self.detect_cross_protocol_arbitrage());
        vulnerabilities.extend(self.detect_flash_loan_farming());
        vulnerabilities.extend(self.detect_bot_detection_bypass());
        vulnerabilities.extend(self.detect_point_decay_exploit());

        vulnerabilities
    }

    fn is_points_contract(&self) -> bool {
        // Look for points/rewards related function signatures
        let points_signatures = [
            &[0xa9, 0x05, 0x9c, 0xbb][..], // getReward() / claimPoints()
            &[0x70, 0xa0, 0x82, 0x31][..], // balanceOf(address) - points balance
            &[0x3d, 0x18, 0xb9, 0x12][..], // getReferralRewards()
            &[0xe6, 0xa4, 0x39, 0x05][..], // calculatePoints()
            &[0x18, 0x16, 0x0d, 0xdd][..], // earnPoints()
        ];

        points_signatures.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_sybil_farming(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points accrual with no sybil resistance
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for point minting/accrual
            if self.bytecode[i] == 0x55 { // SSTORE (updating points balance)
                // Check if based on simple action (no identity verification)
                let simple_action = self.bytecode[i.saturating_sub(30)..i]
                    .windows(1).any(|w| w[0] == 0x33); // Just CALLER check

                // Critical: No unique identifier beyond address
                let no_sybil_protection = !self.bytecode[i.saturating_sub(80)..i+50]
                    .windows(1).any(|w| w[0] == 0xFA || w[0] == 0xF1); // No external verification

                if simple_action && no_sybil_protection {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::SybilFarming,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Points accrue per address without sybil resistance".to_string(),
                        exploit_scenario: "Sybil Farming Attack:\n\
                            1. Protocol gives 100 points per depositor per day\n\
                            2. No verification beyond wallet address\n\
                            3. Attacker creates 1,000 wallets\n\
                            4. Deposits 0.1 ETH in each (100 ETH total)\n\
                            5. Earns 100,000 points per day vs 100 for single user\n\
                            6. Dominates airdrop allocation unfairly\n\
                            7. Single whale gets 1000x normal user's allocation\n\
                            \n\
                            Real examples: Blast, LayerZero, StarkNet point farming".to_string(),
                        remediation: "Add sybil resistance:\n\
                            1. Require proof of humanity (Worldcoin, Gitcoin Passport)\n\
                            2. On-chain reputation scoring\n\
                            3. Minimum activity requirements across time\n\
                            4. Exponential points for larger deposits (favor consolidation)\n\
                            5. Cap points per address\n\
                            6. Retroactive sybil filtering before airdrop".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_circular_farming(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points for deposits that can be immediately withdrawn
        for i in 0..self.bytecode.len().saturating_sub(150) {
            // Look for deposit function giving points
            if self.bytecode[i] == 0x02 { // MUL (calculating points)
                // Check if withdrawal is unrestricted
                let has_immediate_withdrawal = self.bytecode[i+20..i+150]
                    .windows(1).any(|w| w[0] == 0xF1); // CALL (withdrawal)

                // Critical: No lock period or points reduction on withdrawal
                let no_lock_period = !self.bytecode[i.saturating_sub(50)..i+100]
                    .windows(1).any(|w| w[0] == 0x42); // No TIMESTAMP lock check

                if has_immediate_withdrawal && no_lock_period {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::CircularFarming,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Points earned on deposits can be farmed via circular deposit/withdraw".to_string(),
                        exploit_scenario: "Circular Farming Loop:\n\
                            1. Protocol gives 1 point per ETH deposited\n\
                            2. No lock period or withdrawal penalty\n\
                            3. Attacker deposits 1000 ETH, gets 1000 points\n\
                            4. Immediately withdraws 1000 ETH\n\
                            5. Repeats in same transaction 100 times\n\
                            6. Earns 100,000 points from same 1000 ETH\n\
                            7. Costs only gas, dominates point leaderboard\n\
                            \n\
                            Real example: Early Blast points farming (May 2024)".to_string(),
                        remediation: "Prevent circular farming:\n\
                            1. Minimum lock period (7-30 days)\n\
                            2. Points accrue over time, not instantly\n\
                            3. Withdrawal removes proportional points\n\
                            4. One deposit/withdraw per block\n\
                            5. Points based on time-weighted average balance".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_referral_manipulation(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Referral rewards without self-referral prevention
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for referral reward distribution
            if self.bytecode[i] == 0x55 { // SSTORE (referral points)
                // Check if referrer and referee are checked for relationship
                let has_referral_check = self.bytecode[i.saturating_sub(50)..i]
                    .windows(2).any(|w| w[0] == 0x14 && w[1] == 0x15); // EQ check

                // Critical: No prevention of self-referral
                let allows_self_referral = !self.bytecode[i.saturating_sub(80)..i]
                    .windows(1).filter(|w| w[0] == 0x33).count() >= 2; // Not checking CALLER twice

                if !has_referral_check || allows_self_referral {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::ReferralManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Referral system allows self-referral or circular referrals".to_string(),
                        exploit_scenario: "Referral Manipulation:\n\
                            1. Protocol gives 10% referral bonus on deposits\n\
                            2. No check that referrer != referee\n\
                            3. Attacker wallet A refers wallet B (self-owned)\n\
                            4. Wallet B deposits 1000 ETH\n\
                            5. Wallet A gets 100 points as referrer\n\
                            6. Wallet B refers wallet C, C deposits 1000 ETH\n\
                            7. Creates circular referral chain\n\
                            8. All wallets earn extra points from each other\n\
                            \n\
                            Real issue: Friend.tech and similar referral systems".to_string(),
                        remediation: "Secure referral system:\n\
                            1. Prevent referrer == referee\n\
                            2. Detect circular referral chains\n\
                            3. Cap referral depth (max 3 levels)\n\
                            4. Require minimum activity before being referrer\n\
                            5. Cap total referral rewards per user\n\
                            6. Monitor for suspicious referral patterns".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_wash_trading(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points for trading volume without wash detection
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for volume-based points
            if self.bytecode[i] == 0x02 { // MUL (volume * rate = points)
                // Check if transaction is swap/trade
                let is_trade_related = self.bytecode[i.saturating_sub(50)..i]
                    .windows(1).any(|w| w[0] == 0x04 || w[0] == 0x08); // DIV or MOD (pricing)

                // Critical: No wash trading detection
                let no_wash_detection = !self.bytecode[i.saturating_sub(100)..i+50]
                    .windows(1).filter(|w| w[0] == 0x33).count() >= 2; // Not checking multiple addresses

                if is_trade_related && no_wash_detection {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::WashTrading,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Trading volume points without wash trading detection".to_string(),
                        exploit_scenario: "Wash Trading for Points:\n\
                            1. Protocol gives 0.1 points per $1 trading volume\n\
                            2. No detection of self-trading\n\
                            3. Attacker wallet A swaps 1000 ETH <-> USDC\n\
                            4. Wallet B (same owner) swaps back\n\
                            5. Repeats 1000 times per day\n\
                            6. Generates $2M fake volume daily\n\
                            7. Earns 200,000 points with ~$50 in fees\n\
                            8. Legitimate traders get diluted\n\
                            \n\
                            Real example: Blur NFT marketplace wash trading (2023)".to_string(),
                        remediation: "Detect wash trading:\n\
                            1. Track trade counterparties\n\
                            2. Penalize trades between related addresses\n\
                            3. Require minimum time between reverse trades\n\
                            4. Give more points for unique trading pairs\n\
                            5. Use machine learning for pattern detection\n\
                            6. Retroactive removal of wash trading points".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_timestamp_gaming(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Point multipliers based on timestamp
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for timestamp-based multiplier
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                // Check if used for multiplier calculation
                let used_for_multiplier = self.bytecode[i+1..i+50]
                    .windows(1).any(|w| w[0] == 0x02 || w[0] == 0x0A); // MUL or EXP

                // Critical: Timestamp can be manipulated within bounds
                if used_for_multiplier {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::TimestampGaming,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Point multipliers based on timestamp vulnerable to minor manipulation".to_string(),
                        exploit_scenario: "Timestamp Gaming:\n\
                            1. Protocol gives 2x points during 'happy hour' (specific timestamp)\n\
                            2. Miner/validator can manipulate timestamp ±15 seconds\n\
                            3. Attacker bribes miner to set timestamp in happy hour\n\
                            4. Makes large deposit during manipulated timestamp\n\
                            5. Gets 2x points unfairly\n\
                            6. Costs minimal MEV bribe vs point value\n\
                            \n\
                            Lower severity but possible on L1/L2s with timestamp flexibility".to_string(),
                        remediation: "Avoid timestamp-based multipliers:\n\
                            1. Use block number instead of timestamp\n\
                            2. Make multiplier windows wide (hours not minutes)\n\
                            3. Randomize bonus windows (unpredictable)\n\
                            4. Use VRF for random bonus timing\n\
                            5. Avoid predictable timing patterns".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cross_protocol_arbitrage(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points from external protocol interactions
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for external calls that grant points
            if (self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA) { // CALL or STATICCALL
                // Check if followed by point allocation
                let grants_points = self.bytecode[i+1..i+50]
                    .windows(2).any(|w| w[0] == 0x02 && w[1] == 0x55); // MUL + SSTORE

                // Critical: No validation of external protocol response
                let no_response_validation = !self.bytecode[i+1..i+30]
                    .windows(2).any(|w| w[0] == 0x15 && w[1] == 0x57); // ISZERO + JUMPI check

                if grants_points && no_response_validation {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::CrossProtocolArbitrage,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Points granted based on unvalidated external protocol interactions".to_string(),
                        exploit_scenario: "Cross-Protocol Gaming:\n\
                            1. Protocol A gives points for using Protocol B\n\
                            2. No validation of Protocol B response\n\
                            3. Attacker deploys fake Protocol B contract\n\
                            4. Fake contract reports inflated activity\n\
                            5. Protocol A grants points based on fake data\n\
                            6. Attacker farms unlimited points\n\
                            \n\
                            Or: Attacker finds arbitrage between multiple point systems,\n\
                            extracting value from point rate differentials".to_string(),
                        remediation: "Validate external interactions:\n\
                            1. Whitelist approved external protocols\n\
                            2. Verify external contract code\n\
                            3. Use cryptographic proofs of external actions\n\
                            4. Cap points from external sources\n\
                            5. Manual review of high-value integrations".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_flash_loan_farming(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Points based on balance snapshot
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for balance-based point calculation
            if self.bytecode[i] == 0x31 { // BALANCE
                // Check if directly affects points
                let affects_points = self.bytecode[i+1..i+50]
                    .windows(1).any(|w| w[0] == 0x02 || w[0] == 0x55); // MUL or SSTORE

                // Critical: No time-weighted averaging
                let no_time_weighting = !self.bytecode[i+1..i+80]
                    .windows(1).any(|w| w[0] == 0x42 || w[0] == 0x43); // TIMESTAMP or NUMBER

                if affects_points && no_time_weighting {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::FlashLoanFarming,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Points based on instant balance without time-weighting allows flash loan farming".to_string(),
                        exploit_scenario: "Flash Loan Point Farming:\n\
                            1. Protocol snapshot for points at block X\n\
                            2. Points = balance at snapshot time\n\
                            3. Attacker flash loans 100,000 ETH\n\
                            4. Deposits just before snapshot\n\
                            5. Snapshot captures inflated balance\n\
                            6. Withdraws and repays flash loan\n\
                            7. Earned massive points from borrowed capital\n\
                            8. Costs only flash loan fee (~0.05%)\n\
                            \n\
                            Real risk: Many airdrop farming strategies use this".to_string(),
                        remediation: "Prevent flash loan farming:\n\
                            1. Use time-weighted average balance (TWAB)\n\
                            2. Require minimum holding period (1+ blocks)\n\
                            3. Multiple random snapshots\n\
                            4. Points accrue continuously, not snapshot\n\
                            5. Detect and penalize flash loan patterns".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_bot_detection_bypass(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Simple bot detection that can be bypassed
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for bot detection logic
            if self.bytecode[i] == 0x32 { // ORIGIN vs CALLER check
                // Check if this is only bot detection
                let only_origin_check = !self.bytecode[i.saturating_sub(50)..i+50]
                    .windows(1).any(|w| w[0] == 0x3B); // EXTCODESIZE (better bot check)

                // Critical: Simple tx.origin check bypassed by smart wallet
                if only_origin_check {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::BotDetectionBypass,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Bot detection uses only tx.origin which can be bypassed".to_string(),
                        exploit_scenario: "Bot Detection Bypass:\n\
                            1. Protocol blocks contracts: require(tx.origin == msg.sender)\n\
                            2. Intended to prevent bot farming\n\
                            3. Attacker uses smart account (ERC-4337)\n\
                            4. Smart account has EOA signer (tx.origin)\n\
                            5. Automated farming bot runs through smart account\n\
                            6. Bypasses detection while maintaining automation\n\
                            7. Scales to thousands of accounts\n\
                            \n\
                            Note: As account abstraction grows, this becomes easier".to_string(),
                        remediation: "Better bot detection:\n\
                            1. Use behavioral analysis (transaction patterns)\n\
                            2. Rate limiting per address\n\
                            3. Proof of humanity integration\n\
                            4. Entropy-based human verification\n\
                            5. Accept that some automation is inevitable\n\
                            6. Focus on sybil resistance over bot blocking".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_point_decay_exploit(&self) -> Vec<PointsGamingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Point decay calculation errors
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for decay/reduction calculation
            if self.bytecode[i] == 0x03 { // SUB (point reduction)
                // Check if decay rate can underflow
                let potential_underflow = !self.bytecode[i.saturating_sub(20)..i]
                    .windows(2).any(|w| w[0] == 0x11 && w[1] == 0x57); // GT check before SUB

                // Critical: Decay can cause underflow to maximum value
                if potential_underflow {
                    vulnerabilities.push(PointsGamingVulnerability {
                        vulnerability_type: PointsGamingType::PointDecayExploit,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Point decay calculation vulnerable to underflow exploitation".to_string(),
                        exploit_scenario: "Point Decay Underflow:\n\
                            1. Protocol reduces points by 1% per day of inactivity\n\
                            2. User has 100 points\n\
                            3. Decay calculation: points -= (points * days * rate)\n\
                            4. Integer underflow if calculation > current points\n\
                            5. Points wrap to maximum uint256 value\n\
                            6. User suddenly has 2^256 points\n\
                            \n\
                            Lower severity (Solidity 0.8+ has overflow protection)\n\
                            but still issue in Vyper or unchecked blocks".to_string(),
                        remediation: "Safe decay calculation:\n\
                            1. Use checked math (Solidity 0.8+)\n\
                            2. Cap decay at current points (points = 0 minimum)\n\
                            3. Test edge cases thoroughly\n\
                            4. Consider exponential decay instead of linear\n\
                            5. Add safeguards for extreme time periods".to_string(),
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
    fn test_detects_sybil_farming() {
        let bytecode = vec![
            0x33, // CALLER (simple check)
            0x60, 0x64, 0x55, // SSTORE (100 points)
            // No external verification
        ];
        
        let detector = PointsGamingDetector::new(bytecode);
        let vulns = detector.detect_sybil_farming();
        
        assert!(!vulns.is_empty(), "Should detect sybil vulnerability");
        assert_eq!(vulns[0].vulnerability_type, PointsGamingType::SybilFarming);
    }

    #[test]
    fn test_detects_circular_farming() {
        let bytecode = vec![
            0x02, // MUL (calculate points)
            0x60, 0x00, 0x55, // SSTORE (award points)
            vec![0x00; 20].as_slice(), // padding
            0xF1, // CALL (withdrawal available)
            // No timestamp lock
        ].concat();
        
        let detector = PointsGamingDetector::new(bytecode);
        let vulns = detector.detect_circular_farming();
        
        assert!(!vulns.is_empty(), "Should detect circular farming");
        assert_eq!(vulns[0].vulnerability_type, PointsGamingType::CircularFarming);
    }

    #[test]
    fn test_detects_flash_loan_farming() {
        let bytecode = vec![
            0x31, // BALANCE (snapshot)
            0x02, 0x55, // MUL + SSTORE (points from balance)
            // No time weighting
        ];
        
        let detector = PointsGamingDetector::new(bytecode);
        let vulns = detector.detect_flash_loan_farming();
        
        assert!(!vulns.is_empty(), "Should detect flash loan farming");
        assert_eq!(vulns[0].vulnerability_type, PointsGamingType::FlashLoanFarming);
    }
}
