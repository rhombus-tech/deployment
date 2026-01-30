// Orderly Network Cross-Chain Liquidity Detector
// Detects vulnerabilities in cross-chain order book liquidity bridging

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderlyNetworkVulnerability {
    pub location: usize,
    pub vulnerability_type: OrderlyVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrderlyVulnerabilityType {
    CrossChainLiquidityFragmentation, // Liquidity split causes arbitrage
    BridgeDelayExploit,               // Exploit bridge settlement delays
    CrossChainOrderMatching,          // Order matching across chains exploitable
    SettlementRaceCondition,          // Race between chain settlements
    LiquidityPoolImbalance,           // Pool imbalance manipulation
    CrossChainPriceOracle,            // Oracle inconsistency across chains
}

pub struct OrderlyNetworkDetector {
    bytecode: Vec<u8>,
}

impl OrderlyNetworkDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OrderlyNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_liquidity_fragmentation() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::CrossChainLiquidityFragmentation,
                severity: SecuritySeverity::High,
                description: "Cross-chain liquidity not synchronized. Price differences between chains \
                             allow arbitrage that drains liquidity pools.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_bridge_delay_exploit() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::BridgeDelayExploit,
                severity: SecuritySeverity::High,
                description: "Bridge settlement delay not accounted in pricing. Orders can be placed \
                             on one chain and front-run settlement on another.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_cross_chain_matching() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::CrossChainOrderMatching,
                severity: SecuritySeverity::Critical,
                description: "Cross-chain order matching lacks atomicity. Partial fills on one chain \
                             can fail to settle on another causing losses.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_settlement_race() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::SettlementRaceCondition,
                severity: SecuritySeverity::High,
                description: "Multi-chain settlement order not enforced. Trader can manipulate which \
                             chain settles first to maximize profit.".to_string(),
                confidence: 0.80,
            });
        }

        if let Some(loc) = self.detect_pool_imbalance() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::LiquidityPoolImbalance,
                severity: SecuritySeverity::Medium,
                description: "Liquidity pool rebalancing vulnerable. Attacker can cause imbalance \
                             across chains to profit from rebalancing transactions.".to_string(),
                confidence: 0.76,
            });
        }

        if let Some(loc) = self.detect_cross_chain_oracle() {
            vulnerabilities.push(OrderlyNetworkVulnerability {
                location: loc,
                vulnerability_type: OrderlyVulnerabilityType::CrossChainPriceOracle,
                severity: SecuritySeverity::High,
                description: "Price oracles not synchronized across chains. Different prices on \
                             different chains allow exploitation during cross-chain trades.".to_string(),
                confidence: 0.83,
            });
        }

        vulnerabilities
    }

    fn detect_liquidity_fragmentation(&self) -> Option<usize> {
        // Pattern: Liquidity check without cross-chain aggregation
        // SLOAD (local liquidity) → use without STATICCALL (other chains)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (liquidity)
                let mut checks_other_chains = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (bridge query)
                        checks_other_chains = true;
                    }
                    
                    // Liquidity used without cross-chain check
                    if !checks_other_chains && (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_bridge_delay_exploit(&self) -> Option<usize> {
        // Pattern: Price quote without bridge delay consideration
        // Price calculation without TIMESTAMP delta for bridge time
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x04 || self.bytecode[i] == 0x02 {  // DIV/MUL (price)
                let mut considers_bridge_delay = false;
                
                for j in (i.saturating_sub(15))..i {
                    // Bridge delay: TIMESTAMP with ADD (future time)
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (delay)
                                considers_bridge_delay = true;
                            }
                        }
                    }
                }
                
                // Price used for cross-chain without delay
                if !considers_bridge_delay {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_cross_chain_matching(&self) -> Option<usize> {
        // Pattern: Order matching without atomicity guarantee
        // SSTORE (fill order) without lock across chains
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (order fill)
                let mut has_cross_chain_lock = false;
                
                // Look for cross-chain lock mechanism
                for j in (i.saturating_sub(20))..i {
                    // Lock: CALL to bridge with lock flag
                    if self.bytecode[j] == 0xF1 {
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // SLOAD (lock state)
                                has_cross_chain_lock = true;
                            }
                        }
                    }
                }
                
                // Check if this is cross-chain (multiple SSTOREs for state sync)
                let mut sstore_count = 1;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                
                if sstore_count >= 2 && !has_cross_chain_lock {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_settlement_race(&self) -> Option<usize> {
        // Pattern: Multi-chain settlement without ordering
        // Multiple CALL (settle chains) without sequence enforcement
        
        let mut call_count = 0;
        let mut has_sequencing = false;
        let start_window = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0xF1 {  // CALL (settle)
                call_count += 1;
                
                // Check for sequence number between calls
                if call_count >= 2 {
                    for j in (i.saturating_sub(15))..i {
                        if self.bytecode[j] == 0x54 {  // SLOAD (sequence)
                            for k in j+1..(j+5).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x01 {  // ADD (increment)
                                    has_sequencing = true;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check 40-byte windows
            if i % 40 == 39 && call_count >= 2 && !has_sequencing {
                return Some(start_window);
            }
            
            if i % 40 == 0 {
                call_count = 0;
                has_sequencing = false;
            }
        }
        
        None
    }

    fn detect_pool_imbalance(&self) -> Option<usize> {
        // Pattern: Rebalancing without cost check
        // Transfer for rebalancing without fee/slippage validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (transfer for rebalance)
                let mut validates_cost = false;
                
                // Check for cost/slippage validation
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (cost check)
                        validates_cost = true;
                    }
                }
                
                // Check if this is rebalancing (comparing liquidity levels)
                let mut is_rebalancing = false;
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x54 {  // Second SLOAD (compare pools)
                                is_rebalancing = true;
                            }
                        }
                    }
                }
                
                if is_rebalancing && !validates_cost {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cross_chain_oracle(&self) -> Option<usize> {
        // Pattern: Single chain oracle for cross-chain trade
        // One STATICCALL (oracle) used for multi-chain decision
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (oracle)
                let mut oracle_calls = 1;
                let mut has_cross_chain_trade = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {
                        oracle_calls += 1;
                    }
                    
                    // Cross-chain trade: CALL to bridge
                    if self.bytecode[j] == 0xF1 {
                        has_cross_chain_trade = true;
                    }
                }
                
                // Single oracle for cross-chain
                if oracle_calls == 1 && has_cross_chain_trade {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::OrderlyNetwork,
                severity: v.severity,
                description: format!(
                    "Orderly Network {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}
