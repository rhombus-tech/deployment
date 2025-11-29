/// Telegram/Discord Bot Trading Exploit Detector
/// Detects vulnerabilities in trading bot integrations
/// Critical for: Telegram bots, sniper bots, copy trading

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotTradingVulnerability {
    pub vulnerability_type: BotTradingIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BotTradingIssueType {
    BotSignatureReplay,            // Bot signature replay attack
    SniperBotFrontrunning,         // Sniper bot protection bypass
    CopyTradingManipulation,       // Copy trading exploit
    BotWalletCompromise,           // Bot wallet security risk
    AutomatedSlippageExploit,      // Automated slippage manipulation
}

pub struct BotTradingDetector {
    bytecode: Vec<u8>,
}

impl BotTradingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BotTradingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_bot_trading() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_signature_issues());
        vulnerabilities.extend(self.detect_copy_trading_exploits());

        vulnerabilities
    }

    fn detect_signature_issues(&self) -> Vec<BotTradingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Bot order without replay protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_bot_signature(i) {
                if !self.has_replay_protection(i) {
                    vulnerabilities.push(BotTradingVulnerability {
                        vulnerability_type: BotTradingIssueType::BotSignatureReplay,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Trading bot signature without replay protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User signs trade via Telegram bot\n\
                            2. No nonce or timestamp in signature\n\
                            3. Attacker replays same signature\n\
                            4. Multiple trades executed from one signature\n\n\
                            Fix: Include nonce in bot signatures",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_copy_trading_exploits(&self) -> Vec<BotTradingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Copy trading without slippage protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_copy_trade(i) {
                if !self.has_slippage_protection(i) {
                    vulnerabilities.push(BotTradingVulnerability {
                        vulnerability_type: BotTradingIssueType::CopyTradingManipulation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Copy trading without slippage protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Users copy trade leader's transactions\n\
                            2. No slippage limits on copy trades\n\
                            3. Leader frontruns own trade\n\
                            4. Followers receive terrible execution\n\n\
                            Fix: Enforce max slippage on copy trades",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_bot_trading(&self) -> bool {
        // Look for bot-related patterns (heuristic)
        let execute_trade = [0x45, 0x82, 0xf5, 0x71]; // executeTrade()
        let copy_trade = [0x98, 0xa3, 0xd2, 0x47]; // copyTrade()
        
        self.bytecode.windows(4).any(|w| w == execute_trade || w == copy_trade)
    }

    fn has_bot_signature(&self, pos: usize) -> bool {
        // Look for signature verification
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x60 && self.bytecode[pos+1] == 0x01 // ECRECOVER
    }

    fn has_replay_protection(&self, pos: usize) -> bool {
        // Look for nonce check
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 && i + 2 < self.bytecode.len() && self.bytecode[i+2] == 0x55 {
                return true; // SLOAD + SSTORE (nonce)
            }
        }
        false
    }

    fn has_copy_trade(&self, pos: usize) -> bool {
        // Look for copy trade function
        let copy_trade = [0x98, 0xa3, 0xd2, 0x47];
        pos + 4 <= self.bytecode.len() && &self.bytecode[pos..pos+4] == &copy_trade
    }

    fn has_slippage_protection(&self, pos: usize) -> bool {
        // Look for slippage check
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 { // LT (amount > minOut)
                return true;
            }
        }
        false
    }
}
