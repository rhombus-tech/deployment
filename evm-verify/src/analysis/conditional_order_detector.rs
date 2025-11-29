/// Conditional Order Manipulation Detector
/// Detects vulnerabilities in stop-loss, limit orders, TWAP orders
/// Critical for: CoW Protocol, 1inch Fusion, UniswapX, conditional DEX orders

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalOrderVulnerability {
    pub vulnerability_type: ConditionalOrderIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionalOrderIssueType {
    StopLossFrontrunning,          // Stop-loss can be frontrun
    TWAPOrderManipulation,         // TWAP order price manipulation
    ConditionalExecutionBypass,    // Condition check bypassable
    OrderBatchingCensorship,       // Solver/filler can censor orders
    TriggerPriceManipulation,      // Trigger price manipulable
    LimitOrderSandwich,            // Limit order sandwiched
}

pub struct ConditionalOrderDetector {
    bytecode: Vec<u8>,
}

impl ConditionalOrderDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConditionalOrderVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_stop_loss_issues());
        vulnerabilities.extend(self.detect_twap_manipulation());
        vulnerabilities.extend(self.detect_trigger_manipulation());

        vulnerabilities
    }

    fn detect_stop_loss_issues(&self) -> Vec<ConditionalOrderVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Price comparison for stop-loss
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x10 && // LT (price < stopPrice)
               self.is_in_trading_context(i) {
                // Check if price can be manipulated
                if !self.has_twap_or_oracle(i) {
                    vulnerabilities.push(ConditionalOrderVulnerability {
                        vulnerability_type: ConditionalOrderIssueType::StopLossFrontrunning,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "Stop-loss uses spot price (manipulable)".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User sets stop-loss at $100\n\
                            2. Attacker sees stop-loss order\n\
                            3. Attacker manipulates price to $99.99\n\
                            4. Stop-loss triggers, user sells\n\
                            5. Attacker buys cheap, price recovers\n\n\
                            Fix: Use TWAP or Chainlink for trigger price",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_twap_manipulation(&self) -> Vec<ConditionalOrderVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: TWAP order execution
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for observation pattern (Uniswap v3 TWAP)
            let observe = [0x88, 0x38, 0xf3, 0x4c];
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &observe {
                // Check for observation interval validation
                if !self.has_interval_check(i) {
                    vulnerabilities.push(ConditionalOrderVulnerability {
                        vulnerability_type: ConditionalOrderIssueType::TWAPOrderManipulation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        description: "TWAP order without interval validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. TWAP order executes over time\n\
                            2. No validation of observation intervals\n\
                            3. Attacker manipulates during quiet periods\n\
                            4. TWAP reflects manipulated price\n\n\
                            Fix: Ensure minimum observation count & interval",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_trigger_manipulation(&self) -> Vec<ConditionalOrderVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Trigger condition based on manipulable data
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_trigger_pattern(i) {
                // Check if trigger uses secure price source
                if !self.has_oracle_pattern(i) {
                    vulnerabilities.push(ConditionalOrderVulnerability {
                        vulnerability_type: ConditionalOrderIssueType::TriggerPriceManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Trigger condition uses manipulable on-chain data".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Conditional order triggered by AMM price\n\
                            2. Attacker flashes large swap\n\
                            3. Price moves, trigger activates\n\
                            4. Order fills at manipulated price\n\
                            5. Attacker reverses swap, profits\n\n\
                            Fix: Use TWAP or Chainlink oracle",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_in_trading_context(&self, pos: usize) -> bool {
        let swap_selector = [0x38, 0xed, 0x17, 0x39];
        for i in pos.saturating_sub(50)..pos.saturating_add(50).min(self.bytecode.len().saturating_sub(4)) {
            if &self.bytecode[i..i+4] == &swap_selector {
                return true;
            }
        }
        false
    }

    fn has_twap_or_oracle(&self, pos: usize) -> bool {
        // Look for oracle call or TWAP observation
        for i in pos.saturating_sub(50)..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFA { // STATICCALL to oracle
                return true;
            }
        }
        false
    }

    fn has_interval_check(&self, pos: usize) -> bool {
        // Look for interval validation (comparison)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }

    fn has_trigger_pattern(&self, pos: usize) -> bool {
        // Look for comparison + JUMPI (conditional trigger)
        pos + 3 < self.bytecode.len() &&
        (self.bytecode[pos] == 0x10 || self.bytecode[pos] == 0x11) &&
        self.bytecode[pos + 2] == 0x57 // JUMPI
    }

    fn has_oracle_pattern(&self, pos: usize) -> bool {
        self.has_twap_or_oracle(pos)
    }
}
