/// ERC-7540 Asynchronous ERC4626 Vault Detector
///
/// Detects vulnerabilities in ERC-7540 async deposit/redeem mechanisms.
///
/// Standard: ERC-7540 (Final, 2024)
/// Pattern: Request-based deposits/withdrawals with time delays
/// Impact: State manipulation between request and fulfillment

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7540AsyncVaultVulnerability {
    pub vulnerability_type: Erc7540VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7540VulnerabilityType {
    RequestFulfillmentRaceCondition,   // Race between request and fulfill
    PendingRequestManipulation,         // Manipulate vault between request/fulfill
    ClaimableSharesInflation,           // Inflate shares between async operations
    RequestCancellationExploit,         // Cancel request to exploit price
    FulfillmentPriceManipulation,       // Manipulate price at fulfillment
    PendingWithdrawalGriefing,          // DOS pending withdrawals
    AsyncReentrancy,                    // Reenter during async operations
    RequestQueueManipulation,           // Manipulate request queue ordering
    PartialFulfillmentExploit,          // Exploit partial fulfills
    TimestampDependentFulfillment,      // Fulfillment timing manipulation
}

pub struct Erc7540AsyncVaultDetector {
    bytecode: Vec<u8>,
}

impl Erc7540AsyncVaultDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7540AsyncVaultVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_race_condition());
        vulnerabilities.extend(self.detect_price_manipulation());
        vulnerabilities.extend(self.detect_async_reentrancy());
        
        vulnerabilities
    }
    
    fn detect_race_condition(&self) -> Vec<Erc7540AsyncVaultVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Request storage without atomic fulfillment
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut stores_request = false;
            let mut has_lock = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0x55 { // SSTORE (request storage)
                    stores_request = true;
                }
                if self.bytecode[j] == 0x54 { // SLOAD (lock check)
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        has_lock = true;
                    }
                }
            }
            
            if stores_request && !has_lock {
                vulnerabilities.push(Erc7540AsyncVaultVulnerability {
                    vulnerability_type: Erc7540VulnerabilityType::RequestFulfillmentRaceCondition,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Async request/fulfillment has race condition. State can be \
                                manipulated between requestDeposit() and claimDeposit().".to_string(),
                    exploit_scenario: "1. User calls requestDeposit(100 ETH)\n\
                                      2. Request stored: pendingDeposit[user] = 100 ETH\n\
                                      3. Attacker sees request in mempool\n\
                                      4. Front-runs with large deposit to inflate share price\n\
                                      5. Operator calls fulfill(), user gets fewer shares\n\
                                      6. Attacker back-runs with withdrawal\n\
                                      7. User gets 30% fewer shares than expected\n\
                                      8. Lost $30K on $100K deposit\n\
                                      9. Async window = vulnerability window".to_string(),
                    recommendation: "Add request locking during pending period. Record share price \
                                  at request time. Use TWAP for fulfillment price. Add slippage protection. \
                                  Implement request-specific price oracle. Reference: ERC-7540 security considerations.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_price_manipulation(&self) -> Vec<Erc7540AsyncVaultVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Fulfillment uses current price without validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut calculates_shares = false;
            let mut validates_price = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x04 { // DIV (share calculation)
                    calculates_shares = true;
                }
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT (price bounds)
                    validates_price = true;
                }
            }
            
            if calculates_shares && !validates_price {
                vulnerabilities.push(Erc7540AsyncVaultVulnerability {
                    vulnerability_type: Erc7540VulnerabilityType::FulfillmentPriceManipulation,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Share calculation at fulfillment uses spot price without bounds \
                                checking. Vulnerable to sandwich attacks.".to_string(),
                    exploit_scenario: "1. User pending deposit: 50 ETH\n\
                                      2. Operator calls fulfillDeposit() in 24 hours\n\
                                      3. Attacker front-runs fulfillDeposit()\n\
                                      4. Deposits 1000 ETH + donates 500 ETH to vault\n\
                                      5. Share price inflated 2x\n\
                                      6. User's fulfillDeposit() executes\n\
                                      7. Gets 50% fewer shares than expected\n\
                                      8. Attacker back-runs withdrawal with profit\n\
                                      9. User permanently loses 25 ETH value\n\
                                      10. $2.5M stolen from large vaults".to_string(),
                    recommendation: "Use time-weighted average price (TWAP) for fulfillment. \
                                  Add min/max share bounds. Lock share price at request time. \
                                  Implement circuit breakers for price deviations. Add slippage limits.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_async_reentrancy(&self) -> Vec<Erc7540AsyncVaultVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: External call during async operation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut has_pending_state = false;
            let mut has_external_call = false;
            let mut has_reentrancy_guard = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x54 { // SLOAD (pending state)
                    has_pending_state = true;
                }
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xF4 { // CALL/DELEGATECALL
                    has_external_call = true;
                }
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO (guard check)
                        has_reentrancy_guard = true;
                    }
                }
            }
            
            if has_pending_state && has_external_call && !has_reentrancy_guard {
                vulnerabilities.push(Erc7540AsyncVaultVulnerability {
                    vulnerability_type: Erc7540VulnerabilityType::AsyncReentrancy,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Async operation makes external call without reentrancy protection. \
                                Attacker can reenter during pending state.".to_string(),
                    exploit_scenario: "1. User calls requestWithdraw(100 shares)\n\
                                      2. pendingWithdraw[user] = 100\n\
                                      3. Vault calls external hook: IHook(hook).beforeWithdraw()\n\
                                      4. Hook is attacker's malicious contract\n\
                                      5. Attacker reenters: claimWithdraw()\n\
                                      6. pendingWithdraw[user] still = 100 (not cleared)\n\
                                      7. Attacker gets 100 shares worth of assets\n\
                                      8. Original call completes, gives another 100\n\
                                      9. Double-withdrawal steals 100 shares\n\
                                      10. $1M+ drained via async reentrancy".to_string(),
                    recommendation: "Add nonReentrant modifier to all async functions. Update state \
                                  before external calls. Use Checks-Effects-Interactions pattern. \
                                  Consider ReentrancyGuard from OpenZeppelin.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_race_condition() {
        let bytecode = vec![
            0x55, // SSTORE (request storage, no lock)
        ];
        
        let detector = Erc7540AsyncVaultDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc7540VulnerabilityType::RequestFulfillmentRaceCondition
        )));
    }
}
