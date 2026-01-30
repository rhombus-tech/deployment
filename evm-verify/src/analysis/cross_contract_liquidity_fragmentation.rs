/// Cross-Chain Liquidity Fragmentation Attack Detection
/// 
/// Coverage: Circle USDC/USDC.e, Axelar axlUSDC, LayerZero bridged assets ($500M+ fragmentation)
/// Attacks: Canonical vs bridged token arbitrage, depeg amplification, circular bridge drainage

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityFragmentationVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub fragmentation_pattern: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub affected_chains: Vec<String>,
}

pub struct CrossContractLiquidityFragmentationDetector {
    bytecode: Vec<u8>,
}

impl CrossContractLiquidityFragmentationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityFragmentationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Canonical vs Bridged Token Price Divergence
        if self.detect_canonical_bridged_divergence() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Canonical-Bridged Token Arbitrage".to_string(),
                severity: "Critical".to_string(),
                fragmentation_pattern: "Multiple representations of same asset across chains".to_string(),
                description: "Same asset exists as canonical and bridged versions, creating arbitrage via price divergence".to_string(),
                exploit_scenario: "USDC on Arbitrum exists as:\n\
                    - USDC (native Circle, canonical)\n\
                    - USDC.e (bridged via Arbitrum bridge)\n\
                    - axlUSDC (Axelar bridge)\n\
                    - lzUSDC (LayerZero bridge)\n\n\
                    Protocol accepts all as 'USDC' at $1.00 peg\n\
                    Reality: USDC.e trades at $0.998, axlUSDC at $0.995 in thin markets\n\n\
                    Attacker deposits 10M USDC.e (costs $9.98M)\n\
                    Protocol values at 10M * $1.00 = $10M\n\
                    Borrows 8M canonical USDC against collateral\n\
                    Sells collateral USDC.e for $9.98M\n\
                    Nets $1.98M profit from price divergence\n\
                    Protocol stuck with depegged collateral\n\n\
                    Scalable: $50M+ drained from cross-chain protocols".to_string(),
                remediation: "Separate pricing for canonical vs bridged assets, liquidity-weighted oracles, bridge-specific LTV, whitelist canonical only".to_string(),
                affected_chains: vec!["Arbitrum".to_string(), "Optimism".to_string(), "Polygon".to_string(), "Avalanche".to_string()],
            });
        }
        
        // 2. Circular Bridge Arbitrage
        if self.detect_circular_bridge_arbitrage() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Circular Bridge Arbitrage Drainage".to_string(),
                severity: "Critical".to_string(),
                fragmentation_pattern: "Multiple bridge paths for same asset".to_string(),
                description: "Asset can be bridged through multiple paths, creating circular arbitrage that drains bridge reserves".to_string(),
                exploit_scenario: "USDC from Ethereum to Polygon via multiple bridges:\n\
                    Path A: Ethereum → Polygon (official PoS bridge) = USDC.e\n\
                    Path B: Ethereum → Polygon (Axelar) = axlUSDC\n\
                    Path C: Ethereum → Polygon (LayerZero) = lzUSDC\n\n\
                    Each bridge has conversion mechanism to/from native USDC\n\n\
                    Attack:\n\
                    1. Start with 100M USDC on Ethereum\n\
                    2. Bridge via Path A → 100M USDC.e on Polygon\n\
                    3. Convert USDC.e → axlUSDC via DEX (98M due to slippage)\n\
                    4. Bridge axlUSDC → Ethereum via Axelar (98M USDC)\n\
                    5. Bridge 98M back via Path B → 98M axlUSDC\n\
                    6. Convert to lzUSDC, bridge back via LayerZero\n\n\
                    Each cycle extracts 2-5% from bridge reserves\n\
                    After 20 cycles: Bridge reserves depleted\n\
                    Liquidity crisis: Users can't bridge out\n\n\
                    $500M+ bridge reserves at risk".to_string(),
                remediation: "Bridge reserve monitoring, withdrawal limits per asset per epoch, cross-bridge coordination, circuit breakers".to_string(),
                affected_chains: vec!["All L2s".to_string(), "Polygon".to_string(), "Avalanche".to_string()],
            });
        }
        
        // 3. Liquidity Pool Fragmentation Exploit
        if self.detect_liquidity_pool_fragmentation() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Fragmented Liquidity Pool Manipulation".to_string(),
                severity: "High".to_string(),
                fragmentation_pattern: "Thin liquidity across multiple token versions".to_string(),
                description: "Same asset in multiple forms fragments liquidity, making each pool manipulable".to_string(),
                exploit_scenario: "Uniswap on Arbitrum has 4 USDC pools:\n\
                    - USDC/ETH: $50M liquidity\n\
                    - USDC.e/ETH: $20M liquidity\n\
                    - axlUSDC/ETH: $5M liquidity\n\
                    - lzUSDC/ETH: $2M liquidity\n\n\
                    Total fragmented: $77M across 4 pools\n\
                    Should be: $77M in one pool (much more secure)\n\n\
                    Attack on thin pool:\n\
                    1. Flash loan 10M ETH\n\
                    2. Dump into lzUSDC/ETH pool (only $2M liquidity)\n\
                    3. lzUSDC price crashes to $0.50\n\
                    4. Protocol using lzUSDC oracle thinks USDC = $0.50\n\
                    5. Mass liquidations across DeFi\n\
                    6. Attacker buys liquidated positions cheap\n\
                    7. Restore lzUSDC pool, price recovers\n\
                    8. Profit from manipulating thinnest pool\n\n\
                    $100M+ in liquidations from $2M pool manipulation".to_string(),
                remediation: "Aggregate liquidity across token versions, minimum liquidity thresholds, multi-pool TWAP, canonical token priority".to_string(),
                affected_chains: vec!["Arbitrum".to_string(), "Base".to_string(), "Scroll".to_string()],
            });
        }
        
        // 4. Bridge Finality Arbitrage
        if self.detect_bridge_finality_arbitrage() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Bridge Finality Time Arbitrage".to_string(),
                severity: "High".to_string(),
                fragmentation_pattern: "Different bridge finality times create arbitrage windows".to_string(),
                description: "Fast bridges vs slow bridges create price discovery lag exploitable for arbitrage".to_string(),
                exploit_scenario: "Bridging USDC from Ethereum to Arbitrum:\n\
                    - Canonical bridge: 7 days (challenge period)\n\
                    - Hop Protocol: 10 minutes (bonded transfer)\n\
                    - Across: 2 minutes (relayer)\n\
                    - Stargate: instant (liquidity pool)\n\n\
                    Price event: USDC depegs to $0.95 on Ethereum (SVB crisis)\n\n\
                    1. Arbitrum price still $1.00 (price discovery lag)\n\
                    2. Buy 100M USDC on Ethereum @ $0.95 = $95M cost\n\
                    3. Bridge via Stargate (instant) to Arbitrum\n\
                    4. Sell on Arbitrum DEXs @ $1.00 = $100M revenue\n\
                    5. Profit: $5M from bridge speed advantage\n\
                    6. Repeat until Arbitrum price discovers depeg\n\n\
                    Fast bridge becomes single point of risk\n\
                    $500M+ flowed through in crisis (March 2023 actual)".to_string(),
                remediation: "Synchronized pricing across chains, bridge speed limits during volatility, cross-chain price feeds".to_string(),
                affected_chains: vec!["Ethereum".to_string(), "Arbitrum".to_string(), "Optimism".to_string()],
            });
        }
        
        // 5. Multi-Hop Bridge Slippage Amplification
        if self.detect_multihop_slippage_amplification() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Multi-Hop Bridge Slippage Cascade".to_string(),
                severity: "Medium".to_string(),
                fragmentation_pattern: "Slippage compounds across multiple bridge hops".to_string(),
                description: "Bridging through multiple chains amplifies slippage, creating extractable value".to_string(),
                exploit_scenario: "User wants to move 10M USDC: Ethereum → Avalanche → Arbitrum\n\n\
                    Hop 1 (Ethereum → Avalanche via Axelar):\n\
                    - Sent: 10.0M USDC\n\
                    - Received: 9.97M axlUSDC (0.3% bridge fee + slippage)\n\n\
                    Hop 2 (Avalanche → Arbitrum via LayerZero):\n\
                    - Sent: 9.97M axlUSDC\n\
                    - Convert to lzUSDC: 9.94M (0.3% DEX slippage)\n\
                    - Bridge: 9.91M (0.3% bridge fee)\n\n\
                    Total received: 9.91M USDC (0.9% total loss)\n\
                    Lost value: $90K\n\n\
                    Protocol assumes 1:1 bridging\n\
                    Reality: Compounding losses on each hop\n\n\
                    MEV bot opportunity:\n\
                    - Frontrun bridge tx on destination\n\
                    - Extract slippage value\n\
                    - User gets even less than 9.91M\n\n\
                    $50M+ extracted annually from multi-hop bridges".to_string(),
                remediation: "Direct bridge paths, slippage aggregation, minimum output guarantees, MEV protection on bridges".to_string(),
                affected_chains: vec!["All chains".to_string()],
            });
        }
        
        // 6. Wrapped Asset Recursive Fragmentation
        if self.detect_wrapped_asset_recursion() {
            vulnerabilities.push(LiquidityFragmentationVulnerability {
                vulnerability_type: "Wrapped Asset Recursive Fragmentation".to_string(),
                severity: "Critical".to_string(),
                fragmentation_pattern: "Wrapped wrapped assets create recursive depeg risk".to_string(),
                description: "Assets wrapped multiple times create fragmentation cascade when any layer depegs".to_string(),
                exploit_scenario: "Asset evolution across chains:\n\
                    1. USDC (native Ethereum)\n\
                    2. USDC.e (bridged to Arbitrum)\n\
                    3. wUSDC.e (wrapped USDC.e on Arbitrum for yield)\n\
                    4. Bridge wUSDC.e to Optimism → axlwUSDC.e\n\
                    5. Wrap again: wrapped-axlwUSDC.e (4 layers deep!)\n\n\
                    Each layer adds depeg risk\n\
                    Protocol accepts wrapped-axlwUSDC.e as '$1 USDC'\n\n\
                    Attack:\n\
                    1. Layer 1 (USDC): Stable @ $1.00\n\
                    2. Layer 2 (USDC.e): Depeg to $0.998 (thin liquidity)\n\
                    3. Layer 3 (wUSDC.e): Depeg to $0.995 (wrapping lag)\n\
                    4. Layer 4 (axlwUSDC.e): Depeg to $0.990 (bridge lag)\n\
                    5. Layer 5 (wrapped-axlwUSDC.e): Crashes to $0.975\n\n\
                    Protocol using layer 5 as collateral:\n\
                    - Values at $1.00\n\
                    - Reality: $0.975\n\
                    - 2.5% instant bad debt\n\n\
                    Attacker deposits 100M layer-5 tokens (cost: $97.5M)\n\
                    Borrows 80M real USDC\n\
                    Defaults, protocol loses $80M - $97.5M = severe loss\n\n\
                    Recursive wrapping = recursive risk".to_string(),
                remediation: "Ban recursive wrapping, unwrap to canonical before accepting, maximum wrapping depth, liquidity requirements per layer".to_string(),
                affected_chains: vec!["All L2s and sidechains".to_string()],
            });
        }
        
        vulnerabilities
    }
    
    fn detect_canonical_bridged_divergence(&self) -> bool {
        // Pattern: Protocol accepts multiple token addresses as same asset
        let has_multi_token_acceptance = self.bytecode.windows(50).filter(|w| {
            w.windows(4).any(|sig| matches!(sig, [0x70, 0xa0, 0x82, 0x31])) // balanceOf checks
        }).count() > 1;
        
        let no_token_differentiation = !self.bytecode.windows(30).any(|w| {
            w.contains(&0x14) && // EQ (address comparison)
            w.iter().filter(|&&b| b == 0x14).count() > 2 // Multiple address checks
        });
        
        has_multi_token_acceptance && no_token_differentiation
    }
    
    fn detect_circular_bridge_arbitrage(&self) -> bool {
        // Pattern: Bridge contract without reserve monitoring or limits
        let is_bridge = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x8d, 0x96, 0xfd, 0xea] | [0x7c, 0x0a, 0x36, 0x50]) // bridge() or deposit()
        });
        
        let no_reserve_check = !self.bytecode.windows(25).any(|w| {
            w.contains(&0x47) && // SELFBALANCE (reserve check)
            w.contains(&0x10) && // LT (compare against minimum)
            w.contains(&0x57)    // JUMPI (revert if too low)
        });
        
        is_bridge && no_reserve_check
    }
    
    fn detect_liquidity_pool_fragmentation(&self) -> bool {
        // Pattern: DEX pool with no minimum liquidity enforcement
        let is_dex_pool = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x02, 0x2c, 0x0d, 0x9f]) // swap() selector
        });
        
        let no_min_liquidity = !self.bytecode.windows(20).any(|w| {
            w.contains(&0x47) && // SELFBALANCE or reserve check
            w.contains(&0x10) && // LT (minimum liquidity)
            w.contains(&0x57)    // JUMPI (require minimum)
        });
        
        is_dex_pool && no_min_liquidity
    }
    
    fn detect_bridge_finality_arbitrage(&self) -> bool {
        // Pattern: Fast bridge without price staleness check
        let is_fast_bridge = self.bytecode.windows(20).any(|w| {
            !w.contains(&0x42) && // No TIMESTAMP check (instant bridge)
            w.contains(&0xf1)     // CALL (bridge transfer)
        });
        
        let no_price_staleness = !self.bytecode.windows(25).any(|w| {
            w.contains(&0x42) && // TIMESTAMP
            w.contains(&0x03) && // SUB (time difference)
            w.contains(&0x10)    // LT (check if stale)
        });
        
        is_fast_bridge && no_price_staleness
    }
    
    fn detect_multihop_slippage_amplification(&self) -> bool {
        // Pattern: Multi-step bridging without accumulated slippage tracking
        let has_multi_step = self.bytecode.windows(100).filter(|w| {
            w.windows(4).filter(|sig| matches!(sig, [0x8d, 0x96, 0xfd, 0xea])).count() > 1 // Multiple bridge calls
        }).count() > 0;
        
        let no_slippage_accumulation = !self.bytecode.windows(30).any(|w| {
            w.contains(&0x03) && // SUB (calculate slippage)
            w.contains(&0x02) && // MUL (accumulate)
            w.contains(&0x10)    // LT (check against max)
        });
        
        has_multi_step && no_slippage_accumulation
    }
    
    fn detect_wrapped_asset_recursion(&self) -> bool {
        // Pattern: Accepts wrapped tokens without unwrapping to canonical
        let accepts_wrapped = self.bytecode.windows(4).any(|w| {
            matches!(w, [0xd0, 0xe3, 0x0d, 0xb0]) // deposit/wrap selector
        });
        
        let no_unwrap_verification = !self.bytecode.windows(30).any(|w| {
            w.windows(4).any(|sig| matches!(sig, [0x2e, 0x1a, 0x7d, 0x4d])) // underlying() or unwrap check
        });
        
        accepts_wrapped && no_unwrap_verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_canonical_bridged_divergence() {
        let bytecode = vec![
            0x70, 0xa0, 0x82, 0x31, // balanceOf (token 1)
            0x00, 0x00,
            0x70, 0xa0, 0x82, 0x31, // balanceOf (token 2)
            // No differentiation
        ];
        let detector = CrossContractLiquidityFragmentationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("Canonical")));
    }
    
    #[test]
    fn test_circular_bridge() {
        let bytecode = vec![
            0x8d, 0x96, 0xfd, 0xea, // bridge()
            // No reserve monitoring
        ];
        let detector = CrossContractLiquidityFragmentationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("Circular")));
    }
}
