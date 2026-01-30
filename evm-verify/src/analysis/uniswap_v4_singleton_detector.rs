/// Uniswap V4 Singleton Architecture Vulnerability Detector
///
/// Detects vulnerabilities specific to Uniswap V4's singleton contract design.
/// Unlike V2/V3 where each pool is a separate contract, V4 has ALL pools in one contract.
///
/// Real-world context:
/// - $10B+ expected TVL at launch (largest DEX deployment ever)
/// - Single contract holds all pool state → cross-pool attacks possible
/// - Flash accounting system → reentrancy risks across pools
/// - Attack surface: Pool isolation, shared storage, cross-pool manipulation

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapV4SingletonVulnerability {
    pub vulnerability_type: UniswapV4SingletonVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UniswapV4SingletonVulnerabilityType {
    CrossPoolReentrancy,            // Reenter from one pool to manipulate another
    SharedStorageCollision,         // Pool states overwrite each other
    FlashAccountingBypass,          // Delta accounting manipulation
    PoolIsolationFailure,           // One pool's state affects another
    SingletonDOSAttack,             // DOS entire protocol via single contract
    CrossPoolPriceManipulation,     // Manipulate pool A to exploit pool B
    LockDataRaceCondition,          // Multiple locks interfere
    DonateToManipulate,             // Donate to singleton to break accounting
    HookCrossTalk,                  // Hook in pool A affects pool B
    UnlockCallbackExploit,          // Callback during unlock manipulates state
}

pub struct UniswapV4SingletonDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4SingletonDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<UniswapV4SingletonVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Cross-pool reentrancy
        if let Some(vuln) = self.detect_cross_pool_reentrancy() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Shared storage collision
        if let Some(vuln) = self.detect_shared_storage_collision() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Flash accounting bypass
        if let Some(vuln) = self.detect_flash_accounting_bypass() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Pool isolation failure
        if let Some(vuln) = self.detect_pool_isolation_failure() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Cross-pool price manipulation
        if let Some(vuln) = self.detect_cross_pool_manipulation() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_cross_pool_reentrancy(&self) -> Option<UniswapV4SingletonVulnerability> {
        // V4 singleton allows operations on multiple pools in single transaction
        // Attacker can reenter from pool A's hook into pool B
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for external call (hook) followed by pool state access
            let mut has_external_call = false;
            let mut accesses_pool_state = false;
            let mut lacks_reentrancy_guard = true;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // External call (likely hook)
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {
                    has_external_call = true;
                }
                
                // Pool state access (SLOAD/SSTORE)
                if has_external_call && (self.bytecode[j] == 0x54 || self.bytecode[j] == 0x55) {
                    accesses_pool_state = true;
                }
                
                // Reentrancy guard check
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        lacks_reentrancy_guard = false;
                    }
                }
            }
            
            if has_external_call && accesses_pool_state && lacks_reentrancy_guard {
                return Some(UniswapV4SingletonVulnerability {
                    vulnerability_type: UniswapV4SingletonVulnerabilityType::CrossPoolReentrancy,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Singleton contract allows cross-pool reentrancy. Hook callback \
                                from pool A can reenter to manipulate pool B's state before pool A \
                                transaction completes.".to_string(),
                    exploit_scenario: "1. Attacker creates malicious hook on ETH/USDC pool\n\
                                      2. User swaps in ETH/USDC pool\n\
                                      3. Hook callback executes during swap\n\
                                      4. Hook reenters singleton to manipulate USDC/DAI pool\n\
                                      5. USDC/DAI price manipulated while ETH/USDC swap incomplete\n\
                                      6. Attacker drains USDC/DAI pool via arbitrage\n\
                                      7. Returns to ETH/USDC swap completion\n\
                                      8. $100M+ possible if major pools affected\n\
                                      9. Similar to Curve read-only reentrancy but cross-pool".to_string(),
                    recommendation: "Use singleton-wide reentrancy guard. Lock entire contract during \
                                  any pool operation. Implement pool isolation via separate lock counters \
                                  per pool. Add transient storage (EIP-1153) for atomic operations. \
                                  Restrict hook execution context. Reference: V4 locker pattern.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_shared_storage_collision(&self) -> Option<UniswapV4SingletonVulnerability> {
        // All pools share same contract storage - must use proper namespacing
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for storage access without proper namespacing
            let mut has_storage_write = false;
            let mut uses_namespacing = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { // SSTORE
                    has_storage_write = true;
                }
                
                // Namespacing via hash(poolId, slot)
                if self.bytecode[j] == 0x20 { // KECCAK256
                    uses_namespacing = true;
                }
            }
            
            if has_storage_write && !uses_namespacing {
                return Some(UniswapV4SingletonVulnerability {
                    vulnerability_type: UniswapV4SingletonVulnerabilityType::SharedStorageCollision,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Pool state stored without proper namespacing. Multiple pools can \
                                overwrite each other's storage slots, causing data corruption.".to_string(),
                    exploit_scenario: "1. Pool A (ETH/USDC) stores liquidity at slot 0\n\
                                      2. Pool B (USDC/DAI) also stores liquidity at slot 0\n\
                                      3. Adding liquidity to Pool B overwrites Pool A's data\n\
                                      4. Pool A now thinks it has Pool B's liquidity\n\
                                      5. Swappers in Pool A get wrong exchange rate\n\
                                      6. Attacker arbitrages price discrepancy\n\
                                      7. $500M+ at risk if storage collision affects major pools".to_string(),
                    recommendation: "Use namespaced storage: keccak256(abi.encode(poolId, slot)). \
                                  Implement ERC-7201 namespaced storage pattern. Use unique storage \
                                  prefix per pool. Add storage layout tests. Reference: OpenZeppelin \
                                  namespaced storage.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_flash_accounting_bypass(&self) -> Option<UniswapV4SingletonVulnerability> {
        // V4 uses "flash accounting" - tracks deltas instead of actual balances
        // Delta must be settled at end of transaction
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for delta accounting without settlement check
            let mut has_delta_update = false;
            let mut checks_settlement = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Delta update (ADD/SUB to delta storage)
                if (self.bytecode[j] == 0x01 || self.bytecode[j] == 0x03) && 
                   j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x55 {
                    has_delta_update = true;
                }
                
                // Settlement check (delta == 0 at end)
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 3 < self.bytecode.len() && 
                       self.bytecode[j+1] == 0x15 && // ISZERO (checking delta == 0)
                       self.bytecode[j+2] == 0xFD { // REVERT if not
                        checks_settlement = true;
                    }
                }
            }
            
            if has_delta_update && !checks_settlement {
                return Some(UniswapV4SingletonVulnerability {
                    vulnerability_type: UniswapV4SingletonVulnerabilityType::FlashAccountingBypass,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Flash accounting delta is updated but settlement is not enforced. \
                                Attacker can leave unsettled debt, effectively stealing from singleton.".to_string(),
                    exploit_scenario: "1. Attacker calls unlock() to start flash accounting\n\
                                      2. Takes 1000 ETH from pool (delta = -1000 ETH)\n\
                                      3. Calls complex series of operations\n\
                                      4. Exploits bug where settlement check is skipped\n\
                                      5. Transaction completes with delta = -1000 ETH\n\
                                      6. Singleton thinks 1000 ETH was returned\n\
                                      7. Attacker walks away with 1000 ETH\n\
                                      8. Pool permanently missing 1000 ETH\n\
                                      9. $50M+ possible with large flash borrows".to_string(),
                    recommendation: "Always enforce settlement: require(currency.delta() == 0). \
                                  Use lock pattern with automatic settlement check. Add transient \
                                  storage for delta tracking. Implement circuit breakers for large \
                                  deltas. Reference: V4 PoolManager.unlock() implementation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_pool_isolation_failure(&self) -> Option<UniswapV4SingletonVulnerability> {
        // Operations on one pool should never affect another pool
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for global state that affects multiple pools
            let mut modifies_global_state = false;
            let mut lacks_pool_scoping = true;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Global state modification (SSTORE to non-namespaced slot)
                if self.bytecode[j] == 0x55 { // SSTORE
                    modifies_global_state = true;
                }
                
                // Pool scoping (poolId check)
                if self.bytecode[j] == 0x14 { // EQ (checking poolId)
                    lacks_pool_scoping = false;
                }
            }
            
            if modifies_global_state && lacks_pool_scoping {
                return Some(UniswapV4SingletonVulnerability {
                    vulnerability_type: UniswapV4SingletonVulnerabilityType::PoolIsolationFailure,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Global state modification affects multiple pools. Operation on \
                                pool A unintentionally changes behavior of pool B.".to_string(),
                    exploit_scenario: "1. Protocol fee is stored globally (not per-pool)\n\
                                      2. Attacker creates malicious pool with 100% fee\n\
                                      3. Triggers fee update from malicious pool\n\
                                      4. Global fee variable set to 100%\n\
                                      5. All other pools now charge 100% fee\n\
                                      6. Legitimate swappers lose entire swap amount to fees\n\
                                      7. Attacker collects fees from all pools\n\
                                      8. $100M+ possible if exploited on major pools".to_string(),
                    recommendation: "Scope all state to specific poolId. Use poolId as key for all \
                                  storage. Avoid global variables that affect pool behavior. \
                                  Implement pool-specific circuit breakers. Add isolation tests. \
                                  Reference: Diamond proxy storage isolation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_cross_pool_manipulation(&self) -> Option<UniswapV4SingletonVulnerability> {
        // Attacker can use pool A to manipulate oracle/price in pool B
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for price calculation that reads from multiple pools
            let mut reads_multiple_pools = false;
            let mut validates_pool_isolation = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Multiple SLOAD (reading different pool states)
                let sload_count = self.bytecode[j..self.bytecode.len().min(j+15)]
                    .iter()
                    .filter(|&&b| b == 0x54)
                    .count();
                
                if sload_count >= 2 {
                    reads_multiple_pools = true;
                }
                
                // Pool isolation check
                if self.bytecode[j] == 0x14 && // EQ
                   j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0xFD { // REVERT
                    validates_pool_isolation = true;
                }
            }
            
            if reads_multiple_pools && !validates_pool_isolation {
                return Some(UniswapV4SingletonVulnerability {
                    vulnerability_type: UniswapV4SingletonVulnerabilityType::CrossPoolPriceManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Price calculation or oracle reads from multiple pools without \
                                isolation validation. Manipulating pool A can affect pool B's pricing.".to_string(),
                    exploit_scenario: "1. Hook reads TWAP from ETH/USDC and USDC/DAI pools\n\
                                      2. Attacker flash-swaps massive amount in ETH/USDC\n\
                                      3. ETH/USDC price temporarily manipulated\n\
                                      4. Hook calculates ETH/DAI price using manipulated TWAP\n\
                                      5. Attacker uses manipulated price in USDC/DAI pool\n\
                                      6. Drains USDC/DAI via arbitrage\n\
                                      7. $20M+ profit from cross-pool oracle manipulation\n\
                                      8. Similar to Mango Markets $110M exploit pattern".to_string(),
                    recommendation: "Use time-weighted averages per pool. Validate pool isolation for \
                                  price feeds. Implement minimum observation window. Add sanity checks \
                                  for cross-pool prices. Use Chainlink oracles for critical pricing. \
                                  Reference: Uniswap V3 TWAP oracle.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cross_pool_reentrancy() {
        // External call followed by state access, no guard
        let bytecode = vec![
            0xF1, // CALL (hook)
            0x54, // SLOAD (pool state access, no guard)
        ];
        
        let detector = UniswapV4SingletonDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            UniswapV4SingletonVulnerabilityType::CrossPoolReentrancy
        )));
    }
    
    #[test]
    fn test_shared_storage_collision() {
        // SSTORE without namespacing (no KECCAK256)
        let bytecode = vec![
            0x55, // SSTORE (no prior KECCAK256)
        ];
        
        let detector = UniswapV4SingletonDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            UniswapV4SingletonVulnerabilityType::SharedStorageCollision
        )));
    }
    
    #[test]
    fn test_flash_accounting_bypass() {
        // Delta update without settlement check
        let bytecode = vec![
            0x01, // ADD
            0x55, // SSTORE (delta update, no settlement check)
        ];
        
        let detector = UniswapV4SingletonDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            UniswapV4SingletonVulnerabilityType::FlashAccountingBypass
        )));
    }
}
