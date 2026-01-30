/// Cross-Contract NFT Liquidity Flash Crash Detection
/// 
/// Coverage: Blur, NFTfi, Arcade, Blend, BendDAO ($1B+ NFT lending TVL)
/// Attacks: NFT floor manipulation, cross-protocol liquidation cascades, oracle lag exploitation

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NFTLiquidityCrashVulnerability {
    pub vulnerability_type: String,
    pub severity: String,
    pub nft_pattern: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub affected_protocols: Vec<String>,
}

pub struct CrossContractNFTLiquidityCrashDetector {
    bytecode: Vec<u8>,
}

impl CrossContractNFTLiquidityCrashDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<NFTLiquidityCrashVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. NFT Floor Price Manipulation → Liquidation Cascade
        if self.detect_floor_manipulation_cascade() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "NFT Floor Manipulation Cascade".to_string(),
                severity: "Critical".to_string(),
                nft_pattern: "Cross-protocol NFT collateral liquidation".to_string(),
                description: "Attacker can manipulate NFT floor price on one protocol to trigger liquidations on another".to_string(),
                exploit_scenario: "Attacker borrows $500K against 10 Bored Apes on NFTfi at 50% LTV\n\
                    Buys 100 BAYC floor NFTs for $2M\n\
                    Flash-dumps 50 BAYCs on Blur at 40% below floor\n\
                    Blur oracle updates: Floor drops from $100K → $60K\n\
                    NFTfi references Blur oracle → BAYC collateral now under-collateralized\n\
                    Mass liquidations triggered on NFTfi, BendDAO, Arcade\n\
                    Attacker buys liquidated NFTs at 60% discount\n\
                    Floor recovers within hours\n\
                    Profit: $800K from $2M capital in 1 block".to_string(),
                remediation: "Time-weighted average price (TWAP) oracles for NFT floors, multi-oracle aggregation, liquidation delays, price impact limits".to_string(),
                affected_protocols: vec!["NFTfi".to_string(), "Blur".to_string(), "Arcade".to_string(), "BendDAO".to_string()],
            });
        }
        
        // 2. Cross-Protocol Oracle Lag Exploitation
        if self.detect_nft_oracle_lag() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "NFT Oracle Lag Cross-Protocol".to_string(),
                severity: "Critical".to_string(),
                nft_pattern: "Asynchronous NFT price feed exploitation".to_string(),
                description: "Different NFT lending protocols use different oracle update frequencies, creating arbitrage windows".to_string(),
                exploit_scenario: "Protocol A uses Blur real-time floor (1-minute updates)\n\
                    Protocol B uses Reservoir TWAP (1-hour updates)\n\
                    Attacker deposits NFT on Protocol B at stale high price\n\
                    Crashes floor on Blur in 10 minutes\n\
                    Borrows max on Protocol B (still using 1-hour-old price)\n\
                    Defaults on loan, keeps borrowed funds\n\
                    Protocol B stuck with underwater NFT collateral\n\
                    Repeated attack: $5M+ drained from protocol".to_string(),
                remediation: "Synchronized oracle updates, cross-oracle verification, maximum borrow caps per collection, real-time floor tracking".to_string(),
                affected_protocols: vec!["Blend".to_string(), "ParaSpace".to_string(), "JPEG'd".to_string()],
            });
        }
        
        // 3. Thin Liquidity NFT Collections
        if self.detect_thin_liquidity_manipulation() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "Thin Liquidity NFT Manipulation".to_string(),
                severity: "High".to_string(),
                nft_pattern: "Low-volume collection price oracle manipulation".to_string(),
                description: "NFT collections with low trading volume can have floor price manipulated with minimal capital".to_string(),
                exploit_scenario: "Collection 'XYZ Punks' has floor of 10 ETH, but only 2-3 sales/day\n\
                    Attacker deposits 5 XYZ Punks on NFT lending protocol at 10 ETH floor\n\
                    Borrows 25 ETH (50% LTV)\n\
                    Lists 10 XYZ Punks on OpenSea at 3 ETH (fake floor)\n\
                    Oracle sees new 'floor' of 3 ETH\n\
                    Attacker defaults on 25 ETH loan\n\
                    Protocol liquidates collateral worth only 15 ETH\n\
                    Attacker profits 10 ETH, protocol loses 10 ETH\n\
                    Scalable across 50+ thin collections: $500K theft".to_string(),
                remediation: "Minimum liquidity thresholds for collateral, volume-weighted floors, multi-day TWAP, collection whitelisting".to_string(),
                affected_protocols: vec!["All NFT lending protocols".to_string()],
            });
        }
        
        // 4. Sandwich NFT Liquidations
        if self.detect_nft_liquidation_sandwich() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "NFT Liquidation Sandwich Attack".to_string(),
                severity: "High".to_string(),
                nft_pattern: "Frontrun/backrun NFT liquidation auctions".to_string(),
                description: "Attacker manipulates NFT floor right before liquidation auction, then restores it after winning".to_string(),
                exploit_scenario: "Borrower's BAYC collateral nearing liquidation threshold\n\
                    Attacker monitors mempool for liquidation tx\n\
                    Tx1 (frontrun): Flash-dump 20 BAYCs on Blur → floor drops 20%\n\
                    Tx2 (liquidation): Protocol liquidates BAYC at crashed floor\n\
                    Tx3 (attacker wins auction): Buys BAYC for 80% of real value\n\
                    Tx4 (backrun): Buys back dumped NFTs → floor recovers\n\
                    Attacker profits 20% on NFT + keeps borrowed funds\n\
                    Atomic MEV bundle: Risk-free profit".to_string(),
                remediation: "Dutch auction with floor protection, delayed auction start, minimum auction duration, liquidation TWAP pricing".to_string(),
                affected_protocols: vec!["BendDAO".to_string(), "JPEG'd".to_string(), "Drops".to_string()],
            });
        }
        
        // 5. Cross-Collection Correlation Attacks
        if self.detect_collection_correlation_exploit() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "NFT Collection Correlation Cascade".to_string(),
                severity: "Medium".to_string(),
                nft_pattern: "Correlated NFT collection liquidation spiral".to_string(),
                description: "Crashing one blue-chip NFT floor triggers correlated crashes in related collections".to_string(),
                exploit_scenario: "Attacker has collateral across multiple protocols:\n\
                    - BAYC on Protocol A\n\
                    - MAYC on Protocol B (correlated to BAYC)\n\
                    - Azuki on Protocol C\n\
                    Crashes BAYC floor by 30%\n\
                    MAYC floor follows (-25% correlation)\n\
                    Azuki weakens (-15% blue-chip correlation)\n\
                    All three positions now liquidatable\n\
                    Attacker defaults on all loans, walks with borrowed funds\n\
                    Total borrowed: $2M, total loss: $600K\n\
                    Profit: $1.4M from correlated crash".to_string(),
                remediation: "Collection correlation analysis, diversified collateral requirements, correlation-adjusted LTV, stress testing".to_string(),
                affected_protocols: vec!["Multi-protocol NFT lending".to_string()],
            });
        }
        
        // 6. Rehypothecated NFT Collateral
        if self.detect_nft_rehypothecation_risk() {
            vulnerabilities.push(NFTLiquidityCrashVulnerability {
                vulnerability_type: "NFT Collateral Rehypothecation Cascade".to_string(),
                severity: "Critical".to_string(),
                nft_pattern: "Same NFT used as collateral across multiple protocols".to_string(),
                description: "NFT locked on Protocol A, receipt token used as collateral on Protocol B, creating recursive leverage".to_string(),
                exploit_scenario: "User deposits BAYC on BendDAO → receives bBAYC (collateral receipt)\n\
                    Uses bBAYC as collateral on Protocol X → borrows 80 ETH\n\
                    Protocol X treats bBAYC as 'BAYC equivalent'\n\
                    BAYC floor crashes\n\
                    BendDAO liquidates BAYC → bBAYC becomes worthless\n\
                    Protocol X has worthless collateral, 80 ETH lent\n\
                    Total loss amplified by recursive collateral\n\
                    Systemic risk: $50M+ across protocols".to_string(),
                remediation: "Receipt token blacklisting, collateral composition analysis, recursive position detection, rehypothecation limits".to_string(),
                affected_protocols: vec!["BendDAO".to_string(), "Para Space".to_string(), "Unlockd".to_string()],
            });
        }
        
        vulnerabilities
    }
    
    fn detect_floor_manipulation_cascade(&self) -> bool {
        // Pattern: NFT floor oracle dependency + liquidation logic
        let has_nft_oracle = self.bytecode.windows(4).any(|w| {
            // Floor price function selectors: getFloorPrice, latestFloorPrice
            matches!(w, [0x94, 0x49, 0xa0, 0x87] | [0x2f, 0x1a, 0x63, 0xd4])
        });
        
        let has_liquidation_logic = self.bytecode.windows(3).any(|w| {
            w.contains(&0x47) && // SELFBALANCE (transfer value)
            w.contains(&0xf1)    // CALL (execute liquidation)
        });
        
        has_nft_oracle && has_liquidation_logic
    }
    
    fn detect_nft_oracle_lag(&self) -> bool {
        // Pattern: Single oracle source without TWAP or multi-oracle validation
        let has_single_oracle = self.bytecode.windows(20).any(|w| {
            w.contains(&0xf1) && // External CALL (oracle)
            !w.iter().filter(|&&b| b == 0xf1).count() > 1 // Only one oracle call
        });
        
        let no_twap = !self.bytecode.windows(15).any(|w| {
            w.contains(&0x42) || // TIMESTAMP (time-weighted)
            w.contains(&0x43)    // NUMBER (block-weighted)
        });
        
        has_single_oracle && no_twap
    }
    
    fn detect_thin_liquidity_manipulation(&self) -> bool {
        // Pattern: No volume checks or liquidity verification
        let accepts_collateral = self.bytecode.windows(4).any(|w| {
            matches!(w, [0xf2, 0xc2, 0x98, 0xbe]) // deposit() selector
        });
        
        let no_volume_check = !self.bytecode.windows(10).any(|w| {
            w.iter().filter(|&&b| b == 0x11 || b == 0x10).count() >= 2 // Missing volume comparisons
        });
        
        accepts_collateral && no_volume_check
    }
    
    fn detect_nft_liquidation_sandwich(&self) -> bool {
        // Pattern: Immediate liquidation without time delay or TWAP
        let has_liquidation = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x96, 0xcd, 0x4d, 0xdb]) // liquidate() selector
        });
        
        let no_delay = !self.bytecode.windows(20).any(|w| {
            (w.contains(&0x42) && w.contains(&0x01)) || // TIMESTAMP + ADD (delay check)
            (w.contains(&0x43) && w.contains(&0x01))    // NUMBER + ADD (block delay)
        });
        
        has_liquidation && no_delay
    }
    
    fn detect_collection_correlation_exploit(&self) -> bool {
        // Pattern: Multiple NFT collections without correlation analysis
        let multiple_collections = self.bytecode.windows(50).filter(|w| {
            w.windows(4).any(|sig| matches!(sig, [0x23, 0xb8, 0x72, 0xdd])) // transferFrom (NFT deposits)
        }).count() > 1;
        
        let no_correlation_check = !self.bytecode.windows(30).any(|w| {
            w.iter().filter(|&&b| b == 0x02).count() >= 3 // Missing correlation math (MUL operations)
        });
        
        multiple_collections && no_correlation_check
    }
    
    fn detect_nft_rehypothecation_risk(&self) -> bool {
        // Pattern: Accepts receipt tokens as collateral without checking backing
        let accepts_receipt_tokens = self.bytecode.windows(4).any(|w| {
            matches!(w, [0x70, 0xa0, 0x82, 0x31]) // balanceOf (receipt token check)
        });
        
        let no_underlying_verification = !self.bytecode.windows(25).any(|w| {
            w.windows(4).any(|sig| matches!(sig, [0x6f, 0x30, 0x7d, 0xc3])) // underlying() check
        });
        
        accepts_receipt_tokens && no_underlying_verification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nft_floor_manipulation_detection() {
        let bytecode = vec![
            0x94, 0x49, 0xa0, 0x87, // getFloorPrice()
            0x47, // SELFBALANCE
            0xf1, // CALL (liquidation)
        ];
        let detector = CrossContractNFTLiquidityCrashDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("Floor Manipulation")));
    }
    
    #[test]
    fn test_nft_oracle_lag_detection() {
        let bytecode = vec![
            0xf1, // Single oracle CALL
            0x00, 0x00, 0x00, // No TWAP logic
        ];
        let detector = CrossContractNFTLiquidityCrashDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.iter().any(|v| v.vulnerability_type.contains("Oracle Lag")));
    }
}
