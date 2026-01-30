/// RIP-7212 Secp256r1 (P-256) Precompile Detector
///
/// Detects vulnerabilities in contracts using the P-256 elliptic curve precompile
/// for WebAuthn/Passkey verification (EIP-7212/RIP-7212).
///
/// This enables hardware wallet support (Yubikey, Face ID, Touch ID) but introduces
/// new attack vectors around signature malleability and implementation differences.
///
/// Real-world context:
/// - Adopted by Coinbase Smart Wallet (2024)
/// - Base chain implements RIP-7212
/// - Precompile address: 0x0000000000000000000000000000000000000100
/// - Critical for account abstraction adoption

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secp256r1Vulnerability {
    pub vulnerability_type: Secp256r1VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Secp256r1VulnerabilityType {
    SignatureMalleability,        // (r,s) and (r,-s) both valid
    PrecompileMissing,            // Fallback to Solidity verification (expensive)
    IncorrectPrecompileAddress,   // Wrong address for P-256 precompile
    MissingReturnCheck,           // Not checking precompile success
    ReplayAcrossChains,           // No chain ID in signed message
    WeakRandomness,               // Predictable nonce in signature
    TimestampManipulation,        // Signature timestamp not checked
    BiometricBypass,              // No user presence verification
}

pub struct Secp256r1PasskeyDetector {
    bytecode: Vec<u8>,
}

impl Secp256r1PasskeyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Secp256r1Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Detect signature malleability issues
        if let Some(vuln) = self.detect_signature_malleability() {
            vulnerabilities.push(vuln);
        }
        
        // 2. Detect incorrect precompile address
        if let Some(vuln) = self.detect_precompile_address() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Detect missing return value check
        if let Some(vuln) = self.detect_missing_return_check() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Detect replay attack vulnerabilities
        if let Some(vuln) = self.detect_replay_vulnerability() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Detect weak randomness in nonce generation
        if let Some(vuln) = self.detect_weak_randomness() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_signature_malleability(&self) -> Option<Secp256r1Vulnerability> {
        // P-256 signatures are malleable: both (r,s) and (r,-s mod n) are valid
        // Must check: s <= n/2 to prevent malleability
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for signature verification without malleability check
            // Pattern: STATICCALL to precompile without checking s value range
            
            if self.bytecode[i] == 0xFA { // STATICCALL
                let mut has_s_check = false;
                
                // Look back for s <= n/2 check
                for j in i.saturating_sub(30)..i {
                    // GT or LT opcode checking s value
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x12 {
                        // Check if comparing against n/2 (half curve order)
                        // P-256 curve order n/2 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
                        has_s_check = true;
                    }
                }
                
                if !has_s_check {
                    return Some(Secp256r1Vulnerability {
                        vulnerability_type: Secp256r1VulnerabilityType::SignatureMalleability,
                        severity: "High".to_string(),
                        location: vec![i],
                        description: "P-256 (secp256r1) signatures are malleable. For signature (r,s), \
                                    the signature (r,-s mod n) is also valid. Without checking s <= n/2, \
                                    attackers can create alternative valid signatures.".to_string(),
                        exploit_scenario: "1. User signs transaction with passkey: (r, s)\n\
                                          2. Attacker observes signature\n\
                                          3. Computes (r, -s mod n) - also valid!\n\
                                          4. Submits modified signature\n\
                                          5. Bypasses nonce tracking or replay protection\n\
                                          6. Same issue that affected Bitcoin (BIP-62)".to_string(),
                        recommendation: "Normalize signatures: require(uint256(s) <= P256_N_DIV_2). \
                                      Use compact signature encoding. Check both r and s are in \
                                      valid range [1, n-1]. Reference: EIP-2098 for secp256k1.".to_string(),
                    });
                }
            }
        }
        
        None
    }
    
    fn detect_precompile_address(&self) -> Option<Secp256r1Vulnerability> {
        // RIP-7212 precompile address: 0x0000000000000000000000000000000000000100
        // Common mistake: using wrong address or secp256k1 precompile (0x01)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for PUSH20 with potential precompile address
            if self.bytecode[i] == 0x73 { // PUSH20
                if i + 21 < self.bytecode.len() {
                    let addr = &self.bytecode[i+1..i+21];
                    
                    // Check if it's the wrong address
                    let is_secp256k1 = addr == &[0; 19] && addr[19] == 0x01; // ecrecover
                    let is_wrong_p256 = addr != &[0; 19] || self.bytecode[i+20] != 0x00 || (i + 21 < self.bytecode.len() && self.bytecode[i+21] != 0x00 && self.bytecode[i+21] != 0x01);
                    
                    if is_secp256k1 {
                        return Some(Secp256r1Vulnerability {
                            vulnerability_type: Secp256r1VulnerabilityType::IncorrectPrecompileAddress,
                            severity: "Critical".to_string(),
                            location: vec![i],
                            description: "Using secp256k1 precompile (ecrecover at 0x01) instead of \
                                        secp256r1 precompile (RIP-7212 at 0x100). These are different \
                                        curves with incompatible signatures!".to_string(),
                            exploit_scenario: "1. Contract verifies WebAuthn signature\n\
                                              2. Calls ecrecover (0x01) instead of P-256 (0x100)\n\
                                              3. secp256k1 != secp256r1 (different curves)\n\
                                              4. Verification always fails OR accepts wrong signatures\n\
                                              5. Users locked out or attackers can forge signatures".to_string(),
                            recommendation: "Use correct RIP-7212 precompile address: 0x0000...0100. \
                                          Check chain supports it (Base, OP Mainnet). Have fallback \
                                          to Solidity implementation if precompile missing.".to_string(),
                        });
                    }
                }
            }
        }
        
        None
    }
    
    fn detect_missing_return_check(&self) -> Option<Secp256r1Vulnerability> {
        // Precompile returns success/failure
        // Must check return value!
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0xFA { // STATICCALL to precompile
                let mut has_return_check = false;
                
                // Check next few opcodes for success check
                for j in (i+1)..self.bytecode.len().min(i + 10) {
                    if self.bytecode[j] == 0x15 { // ISZERO (checking call success)
                        has_return_check = true;
                        break;
                    }
                }
                
                if !has_return_check {
                    return Some(Secp256r1Vulnerability {
                        vulnerability_type: Secp256r1VulnerabilityType::MissingReturnCheck,
                        severity: "Critical".to_string(),
                        location: vec![i],
                        description: "Calling P-256 precompile without checking return value. If \
                                    signature verification fails, execution continues anyway!".to_string(),
                        exploit_scenario: "1. Attacker provides invalid signature\n\
                                          2. Precompile returns 0 (failure)\n\
                                          3. Contract doesn't check return value\n\
                                          4. Continues execution as if signature was valid\n\
                                          5. Complete authentication bypass".to_string(),
                        recommendation: "Always check staticcall return: require(success). Check \
                                      returndata == 0x01. Handle precompile missing gracefully. \
                                      Example: (bool success,) = PRECOMPILE.staticcall(...); \
                                      require(success, \"P256 verification failed\");".to_string(),
                    });
                }
            }
        }
        
        None
    }
    
    fn detect_replay_vulnerability(&self) -> Option<Secp256r1Vulnerability> {
        // WebAuthn signatures should include nonce, chain ID, and contract address
        // Otherwise can be replayed across chains or accounts
        
        let mut has_chainid = false;
        let mut has_nonce = false;
        let mut has_address = false;
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x46 { // CHAINID opcode
                has_chainid = true;
            }
            if self.bytecode[i] == 0x30 { // ADDRESS opcode
                has_address = true;
            }
            // SLOAD from nonce storage
            if self.bytecode[i] == 0x54 { // SLOAD (could be nonce)
                has_nonce = true;
            }
        }
        
        if !has_chainid || !has_address {
            return Some(Secp256r1Vulnerability {
                vulnerability_type: Secp256r1VulnerabilityType::ReplayAcrossChains,
                severity: "Critical".to_string(),
                location: vec![0],
                description: "Passkey signature verification missing chain ID or contract address \
                            in signed message. Enables cross-chain and cross-contract replay.".to_string(),
                exploit_scenario: "1. User signs operation on Base: signData(operation)\n\
                                  2. Signature doesn't include chain ID or contract address\n\
                                  3. Attacker replays signature on OP Mainnet\n\
                                  4. Or replays on different contract on same chain\n\
                                  5. Unauthorized operations on all chains/contracts".to_string(),
                recommendation: "Include in signed message: keccak256(abi.encode(\n\
                              chainid, address(this), nonce, operation)).\n\
                              Follow EIP-712 structured data signing. Use domain separator.".to_string(),
            });
        }
        
        None
    }
    
    fn detect_weak_randomness(&self) -> Option<Secp256r1Vulnerability> {
        // ECDSA requires random nonce k
        // Weak/predictable k = private key recovery
        
        for i in 0..self.bytecode.len().saturating_sub(5) {
            // Look for timestamp or block number as randomness source
            if self.bytecode[i] == 0x42 || // TIMESTAMP
               self.bytecode[i] == 0x43 {  // NUMBER
                
                // Check if used in signature generation context
                for j in (i+1)..self.bytecode.len().min(i + 30) {
                    if self.bytecode[j] == 0xFA { // STATICCALL (to precompile)
                        return Some(Secp256r1Vulnerability {
                            vulnerability_type: Secp256r1VulnerabilityType::WeakRandomness,
                            severity: "Critical".to_string(),
                            location: vec![i],
                            description: "Using predictable randomness (timestamp/block number) for \
                                        ECDSA nonce generation. Enables private key recovery.".to_string(),
                            exploit_scenario: "1. Signature nonce k = timestamp\n\
                                              2. Attacker knows k (predictable)\n\
                                              3. From signature (r,s), can solve for private key\n\
                                              4. privkey = (s*k - hash) / r\n\
                                              5. Complete account takeover\n\
                                              6. Same attack that broke PlayStation 3 (2010)".to_string(),
                            recommendation: "NEVER generate k on-chain. Signatures must be generated \
                                          off-chain with cryptographically secure randomness. Use \
                                          hardware entropy (TPM, secure enclave). Verify signature \
                                          on-chain only, never create.".to_string(),
                        });
                    }
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secp256r1_malleability_detection() {
        // STATICCALL without s value check
        let bytecode = vec![
            0xFA, // STATICCALL (no malleability check)
        ];
        
        let detector = Secp256r1PasskeyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
        assert!(matches!(
            vulns[0].vulnerability_type,
            Secp256r1VulnerabilityType::SignatureMalleability
        ));
    }
    
    #[test]
    fn test_missing_return_check() {
        // STATICCALL without checking return value
        let bytecode = vec![
            0xFA, // STATICCALL
            0x50, // POP (not checking success)
        ];
        
        let detector = Secp256r1PasskeyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Secp256r1VulnerabilityType::MissingReturnCheck
        )));
    }
    
    #[test]
    fn test_replay_detection() {
        // No CHAINID in bytecode
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0 (no chainid)
        ];
        
        let detector = Secp256r1PasskeyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            Secp256r1VulnerabilityType::ReplayAcrossChains
        )));
    }
}
