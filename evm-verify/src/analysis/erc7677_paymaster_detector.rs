/// ERC-7677 Paymaster Web Service Vulnerability Detector
///
/// Detects vulnerabilities in ERC-7677 paymaster implementations.
/// Paymasters sponsor gas for users, enabling gasless transactions.
///
/// Real-world context:
/// - $1B+ in AA transactions using paymasters
/// - Pimlico, Biconomy, Alchemy all implement ERC-7677
/// - Attack surface: Paymaster draining, sponsorship manipulation, signature replay
/// - Risk: One paymaster exploit can drain all sponsored funds

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7677PaymasterVulnerability {
    pub vulnerability_type: Erc7677PaymasterVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7677PaymasterVulnerabilityType {
    UnrestrictedSponsorshipDrain,   // Anyone can drain paymaster funds
    PaymasterSignatureReplay,       // Signature replayed across chains/nonces
    GasEstimationManipulation,      // Gas estimation inflated to drain paymaster
    UserOperationFrontrunning,      // Frontrun with inflated gas
    PaymasterDataValidationMissing, // Paymaster data not validated
    SponsorshipLimitBypass,         // Per-user sponsorship limits bypassed
    PaymasterPostOpDOS,             // postOp execution causes DOS
    CrossChainPaymasterReplay,      // Paymaster signature replayed cross-chain
    PaymasterWhitelistBypass,       // Whitelist/blacklist bypassed
    UnlimitedPaymasterExposure,     // No cap on paymaster risk exposure
}

pub struct Erc7677PaymasterDetector {
    bytecode: Vec<u8>,
}

impl Erc7677PaymasterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7677PaymasterVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Unrestricted sponsorship drain
        if let Some(vuln) = self.detect_sponsorship_drain() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Paymaster signature replay
        if let Some(vuln) = self.detect_signature_replay() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Gas estimation manipulation
        if let Some(vuln) = self.detect_gas_manipulation() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Paymaster data validation missing
        if let Some(vuln) = self.detect_missing_validation() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Sponsorship limit bypass
        if let Some(vuln) = self.detect_sponsorship_limit_bypass() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_sponsorship_drain(&self) -> Option<Erc7677PaymasterVulnerability> {
        // validatePaymasterUserOp must have proper authorization
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for gas payment logic
            let mut has_gas_payment = false;
            let mut has_authorization = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Gas payment (paymaster paying for user)
                if self.bytecode[j] == 0x03 && self.bytecode[j+1] == 0x55 { // SUB + SSTORE (balance reduction)
                    has_gas_payment = true;
                }
                
                // Authorization (signature or whitelist check)
                if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x54 { // ECRECOVER/SLOAD
                    has_authorization = true;
                }
            }
            
            if has_gas_payment && !has_authorization {
                return Some(Erc7677PaymasterVulnerability {
                    vulnerability_type: Erc7677PaymasterVulnerabilityType::UnrestrictedSponsorshipDrain,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Paymaster pays gas without validating user authorization. Anyone \
                                can drain paymaster funds by submitting unlimited sponsored transactions.".to_string(),
                    exploit_scenario: "1. Paymaster has $10M to sponsor transactions\n\
                                      2. No whitelist or signature validation\n\
                                      3. Attacker creates 1M fake user operations\n\
                                      4. Each operation costs $10 gas (sponsored by paymaster)\n\
                                      5. Paymaster pays $10M total\n\
                                      6. Attacker profits from gas refund/arbitrage\n\
                                      7. Paymaster completely drained\n\
                                      8. Similar to gas griefing but steals funds\n\
                                      9. All Pimlico/Biconomy paymasters at risk if misconfigured".to_string(),
                    recommendation: "Require authorization: (1) Validate signature from paymaster backend, \
                                  (2) Check user whitelist, (3) Verify sponsorship limits per user, \
                                  (4) Add rate limiting, (5) Implement reputation system. Use ERC-7677 \
                                  standard validation. Add paymaster deposit caps.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_signature_replay(&self) -> Option<Erc7677PaymasterVulnerability> {
        // Paymaster signatures must be replay-protected
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for signature verification
            let mut has_signature_check = false;
            let mut has_nonce_validation = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x01 { // ECRECOVER
                    has_signature_check = true;
                }
                
                // Nonce validation (prevents replay)
                if self.bytecode[j] == 0x54 { // SLOAD (loading nonce)
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ (checking nonce)
                        has_nonce_validation = true;
                    }
                }
            }
            
            if has_signature_check && !has_nonce_validation {
                return Some(Erc7677PaymasterVulnerability {
                    vulnerability_type: Erc7677PaymasterVulnerabilityType::PaymasterSignatureReplay,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Paymaster signature verification lacks nonce validation. Same signature \
                                can be replayed multiple times, draining paymaster.".to_string(),
                    exploit_scenario: "1. User gets paymaster signature for $10 gas sponsorship\n\
                                      2. Signature doesn't include nonce\n\
                                      3. User submits operation, paymaster pays $10\n\
                                      4. User replays same signature 1000 times\n\
                                      5. Paymaster pays $10,000 (100x attack)\n\
                                      6. Or attacker intercepts signature, replays across chains\n\
                                      7. Same signature works on all EVM chains\n\
                                      8. $10 turns into $100K exploit\n\
                                      9. Similar to Permit2 signature replay attacks".to_string(),
                    recommendation: "Include nonce in signature: sign(userOp, nonce, validUntil, chainId). \
                                  Track used nonces on-chain. Add validUntil timestamp. Include chain ID \
                                  to prevent cross-chain replay. Use EIP-712 domain separation. \
                                  Reference: Permit2 nonce management.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_gas_manipulation(&self) -> Option<Erc7677PaymasterVulnerability> {
        // Gas estimates must be validated against actual usage
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for gas calculation
            let mut calculates_gas = false;
            let mut validates_actual_gas = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Gas calculation (likely MUL for gas * price)
                if self.bytecode[j] == 0x02 { // MUL
                    calculates_gas = true;
                }
                
                // Actual gas validation (comparing estimate vs actual)
                if self.bytecode[j] == 0x5A { // GAS opcode
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x10 { // LT (checking limit)
                        validates_actual_gas = true;
                    }
                }
            }
            
            if calculates_gas && !validates_actual_gas {
                return Some(Erc7677PaymasterVulnerability {
                    vulnerability_type: Erc7677PaymasterVulnerabilityType::GasEstimationManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Paymaster doesn't validate actual gas usage against estimates. Users \
                                can inflate gas estimates to drain more funds from paymaster.".to_string(),
                    exploit_scenario: "1. User requests paymaster sponsorship for operation\n\
                                      2. Claims operation needs 1M gas\n\
                                      3. Paymaster sponsors based on estimate\n\
                                      4. Operation actually uses 100K gas (10x less)\n\
                                      5. User gets refund for 900K unused gas\n\
                                      6. Repeat 1000 times → $500K profit from gas refunds\n\
                                      7. Paymaster loses funds on every transaction\n\
                                      8. Similar to gas griefing but profitable".to_string(),
                    recommendation: "Validate gas usage: (1) Compare actual gas used vs estimated, \
                                  (2) Cap maximum gas per operation, (3) Use postOp to verify, \
                                  (4) Add penalty for large deviations, (5) Implement gas oracle. \
                                  Reference: ERC-4337 gas validation.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_missing_validation(&self) -> Option<Erc7677PaymasterVulnerability> {
        // paymasterAndData must be properly validated
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for paymaster data processing
            let mut processes_paymaster_data = false;
            let mut validates_data = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Data processing (CALLDATALOAD)
                if self.bytecode[j] == 0x35 { // CALLDATALOAD
                    processes_paymaster_data = true;
                }
                
                // Validation (signature check or data verification)
                if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x20 { // ECRECOVER/KECCAK256
                    validates_data = true;
                }
            }
            
            if processes_paymaster_data && !validates_data {
                return Some(Erc7677PaymasterVulnerability {
                    vulnerability_type: Erc7677PaymasterVulnerabilityType::PaymasterDataValidationMissing,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Paymaster processes paymasterAndData without validation. Malformed \
                                or malicious data can cause unexpected behavior or bypass restrictions.".to_string(),
                    exploit_scenario: "1. Paymaster expects: paymasterAndData = [address, signature, validUntil]\n\
                                      2. No validation of data format\n\
                                      3. Attacker sends: [address, garbage, 0]\n\
                                      4. Paymaster processes garbage as signature\n\
                                      5. Signature 'validation' passes due to bad logic\n\
                                      6. Or attacker sends zero validUntil (infinite validity)\n\
                                      7. Paymaster sponsors transaction indefinitely\n\
                                      8. $100M paymaster funds at risk".to_string(),
                    recommendation: "Validate paymasterAndData: (1) Check data length, (2) Verify signature \
                                  format, (3) Validate validUntil is in future, (4) Check paymaster address \
                                  matches, (5) Add data schema validation. Use strict ABI decoding. \
                                  Add data hash verification.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_sponsorship_limit_bypass(&self) -> Option<Erc7677PaymasterVulnerability> {
        // Per-user sponsorship limits must be enforced
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for sponsorship tracking
            let mut tracks_sponsorship = false;
            let mut enforces_limit = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Sponsorship tracking (SLOAD for user balance)
                if self.bytecode[j] == 0x54 { // SLOAD
                    tracks_sponsorship = true;
                }
                
                // Limit enforcement (LT + REVERT)
                if self.bytecode[j] == 0x10 { // LT
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0xFD { // REVERT
                        enforces_limit = true;
                    }
                }
            }
            
            if tracks_sponsorship && !enforces_limit {
                return Some(Erc7677PaymasterVulnerability {
                    vulnerability_type: Erc7677PaymasterVulnerabilityType::SponsorshipLimitBypass,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Paymaster tracks per-user sponsorship but doesn't enforce limits. \
                                Users can exceed allocated sponsorship and drain paymaster.".to_string(),
                    exploit_scenario: "1. Paymaster allows $100 sponsorship per user\n\
                                      2. Limit tracked but not enforced\n\
                                      3. User submits $500 worth of operations\n\
                                      4. All operations sponsored (5x limit)\n\
                                      5. User creates 1000 Sybil accounts\n\
                                      6. Each drains $500 instead of $100\n\
                                      7. $500K stolen instead of $100K budget\n\
                                      8. Paymaster insolvent".to_string(),
                    recommendation: "Enforce limits: require(userSpent + currentOp <= userLimit). \
                                  Revert if limit exceeded. Implement global paymaster cap. Add \
                                  circuit breakers. Use time-based limits (daily/hourly). Add \
                                  reputation multipliers for trusted users.".to_string(),
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
    fn test_sponsorship_drain() {
        // Gas payment without authorization
        let bytecode = vec![
            0x03, // SUB
            0x55, // SSTORE (payment without ECRECOVER/SLOAD check)
        ];
        
        let detector = Erc7677PaymasterDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc7677PaymasterVulnerabilityType::UnrestrictedSponsorshipDrain
        )));
    }
    
    #[test]
    fn test_signature_replay() {
        // ECRECOVER without nonce validation
        let bytecode = vec![
            0x01, // ECRECOVER (no SLOAD for nonce)
        ];
        
        let detector = Erc7677PaymasterDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc7677PaymasterVulnerabilityType::PaymasterSignatureReplay
        )));
    }
    
    #[test]
    fn test_gas_manipulation() {
        // Gas calculation without validation
        let bytecode = vec![
            0x02, // MUL (gas calculation, no GAS opcode validation)
        ];
        
        let detector = Erc7677PaymasterDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Erc7677PaymasterVulnerabilityType::GasEstimationManipulation
        )));
    }
}
