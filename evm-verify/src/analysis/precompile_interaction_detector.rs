/// Precompile Interaction Vulnerability Detector
///
/// Detects dangerous interactions with Ethereum precompiled contracts (addresses 0x01-0x0a+).
/// Precompiles are special system contracts with native implementations.
///
/// Critical precompiles:
/// - 0x01: ecrecover - signature recovery (most dangerous)
/// - 0x02: SHA2-256 hash
/// - 0x03: RIPEMD-160 hash
/// - 0x04: identity (datacopy)
/// - 0x05: modexp - modular exponentiation
/// - 0x06: ecAdd - elliptic curve addition (BN256)
/// - 0x07: ecMul - elliptic curve multiplication (BN256)
/// - 0x08: ecPairing - elliptic curve pairing (BN256)
/// - 0x09: blake2f - BLAKE2 compression function
/// - 0x0a: point evaluation (EIP-4844)
///
/// Why dangerous:
/// - ecrecover returns address(0) on invalid signature (often unchecked!)
/// - Incorrect gas estimation for precompiles
/// - Return data size validation missing
/// - Signature malleability with ecrecover
/// - BLS/BN256 invalid curve point acceptance
///
/// Real exploits:
/// - Ronin Bridge: $625M - ecrecover validation bypass
/// - Multiple signature validation bugs: $50M+ cumulative
/// - Invalid curve point acceptance causing consensus failures
/// - DoS via expensive modexp calls
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableSignatureValidator {
///     mapping(address => bool) public authorized;
///     
///     function validateAndExecute(
///         bytes32 hash,
///         uint8 v, bytes32 r, bytes32 s,
///         address target, bytes calldata data
///     ) external {
///         // ❌ CRITICAL: ecrecover returns address(0) on invalid sig!
///         address signer = ecrecover(hash, v, r, s);
///         
///         // If authorized[address(0)] = true, anyone can execute!
///         require(authorized[signer], "Not authorized");
///         
///         target.call(data);
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileVulnerability {
    pub vulnerability_type: PrecompileIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub precompile_address: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrecompileIssueType {
    EcrecoverUncheckedZero,           // ecrecover result not checked for address(0)
    EcrecoverSignatureMalleability,   // No check for signature malleability
    PrecompileGasEstimation,          // Incorrect gas estimation for precompile
    PrecompileReturnDataUnchecked,    // Return data not validated
    ModexpDoS,                        // Unbounded modexp causing DoS
    InvalidCurvePoint,                // BN256 operations without point validation
    Blake2fIncorrectRounds,           // blake2f with attacker-controlled rounds
}

pub struct PrecompileInteractionDetector {
    bytecode: Vec<u8>,
}

impl PrecompileInteractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PrecompileVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_ecrecover_unchecked());
        vulnerabilities.extend(self.detect_ecrecover_malleability());
        vulnerabilities.extend(self.detect_modexp_dos());
        vulnerabilities.extend(self.detect_bn256_invalid_points());

        vulnerabilities
    }

    // ============ ECRECOVER UNCHECKED ZERO ============
    
    fn detect_ecrecover_unchecked(&self) -> Vec<PrecompileVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALL/STATICCALL to address 0x01 (ecrecover)
        // followed by using return value WITHOUT zero check
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for STATICCALL or CALL to address 0x01
            if (self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xFA) && // CALL or STATICCALL
               self.is_call_to_ecrecover(i) {
                
                // Check if return value is checked for zero
                if !self.has_zero_address_check_after(i) {
                    vulnerabilities.push(PrecompileVulnerability {
                        vulnerability_type: PrecompileIssueType::EcrecoverUncheckedZero,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "ecrecover result not checked for address(0)".to_string(),
                        exploit_scenario: format!(
                            "ECRECOVER UNCHECKED ZERO at position {}:\n\
                            \n\
                            CRITICAL VULNERABILITY:\n\
                            ecrecover returns address(0) on invalid/malformed signatures.\n\
                            If not checked, attacker can bypass signature validation.\n\
                            \n\
                            VULNERABLE CODE:\n\
                            ```solidity\n\
                            contract VulnerableValidator {{\n\
                                mapping(address => bool) public isValidator;\n\
                                \n\
                                function executeWithSignature(\n\
                                    bytes32 hash,\n\
                                    uint8 v, bytes32 r, bytes32 s,\n\
                                    address target,\n\
                                    bytes calldata data\n\
                                ) external {{\n\
                                    // ❌ CRITICAL: No zero check!\n\
                                    address signer = ecrecover(hash, v, r, s);\n\
                                    \n\
                                    require(isValidator[signer], 'Not validator');\n\
                                    \n\
                                    target.call(data);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK:\n\
                            ```solidity\n\
                            // Step 1: Attacker sets isValidator[address(0)] = true\n\
                            // (via vulnerability, governance, or initial setup bug)\n\
                            \n\
                            // Step 2: Attacker calls with INVALID signature\n\
                            executeWithSignature(\n\
                                bytes32(0),\n\
                                0,  // Invalid v\n\
                                bytes32(0),  // Invalid r\n\
                                bytes32(0),  // Invalid s\n\
                                victimContract,\n\
                                maliciousCalldata\n\
                            );\n\
                            \n\
                            // ecrecover(invalid params) = address(0)\n\
                            // isValidator[address(0)] = true\n\
                            // Signature check passes!\n\
                            // Attacker executes arbitrary call\n\
                            ```\n\
                            \n\
                            REAL WORLD: RONIN BRIDGE HACK - $625 MILLION\n\
                            \n\
                            Similar pattern (simplified):\n\
                            ```solidity\n\
                            contract RoninBridge {{\n\
                                address[] public validators;\n\
                                mapping(address => bool) public isValidator;\n\
                                \n\
                                function submitWithdrawal(\n\
                                    uint256 amount,\n\
                                    bytes[] calldata signatures\n\
                                ) external {{\n\
                                    bytes32 hash = keccak256(abi.encode(amount));\n\
                                    \n\
                                    uint256 validSigs = 0;\n\
                                    for (uint i = 0; i < signatures.length; i++) {{\n\
                                        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signatures[i]);\n\
                                        \n\
                                        address signer = ecrecover(hash, v, r, s);\n\
                                        // ❌ If isValidator[address(0)] somehow true...\n\
                                        if (isValidator[signer]) {{\n\
                                            validSigs++;\n\
                                        }}\n\
                                    }}\n\
                                    \n\
                                    require(validSigs >= threshold, 'Not enough signatures');\n\
                                    \n\
                                    // Process withdrawal\n\
                                    withdraw(amount);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            How Address(0) Gets Authorized:\n\
                            \n\
                            Scenario 1: Initialization Bug\n\
                            ```solidity\n\
                            function addValidator(address validator) external onlyOwner {{\n\
                                // ❌ No zero check\n\
                                isValidator[validator] = true;\n\
                            }}\n\
                            // Owner accidentally adds address(0)\n\
                            ```\n\
                            \n\
                            Scenario 2: Array Initialization\n\
                            ```solidity\n\
                            // Array grows, uninitialized slots = address(0)\n\
                            validators.push(); // Now validators[length-1] = address(0)\n\
                            isValidator[validators[validators.length-1]] = true;\n\
                            ```\n\
                            \n\
                            Scenario 3: Deletion Bug\n\
                            ```solidity\n\
                            function removeValidator(uint256 index) external {{\n\
                                delete validators[index]; // Sets to address(0)\n\
                                // If isValidator not updated, address(0) remains valid\n\
                            }}\n\
                            ```\n\
                            \n\
                            CORRECT IMPLEMENTATION:\n\
                            ```solidity\n\
                            function executeWithSignature(...) external {{\n\
                                address signer = ecrecover(hash, v, r, s);\n\
                                \n\
                                // ✓ ALWAYS check for zero!\n\
                                require(signer != address(0), 'Invalid signature');\n\
                                require(isValidator[signer], 'Not validator');\n\
                                \n\
                                target.call(data);\n\
                            }}\n\
                            \n\
                            // Also protect validator management:\n\
                            function addValidator(address validator) external onlyOwner {{\n\
                                require(validator != address(0), 'Zero address');\n\
                                isValidator[validator] = true;\n\
                            }}\n\
                            ```\n\
                            \n\
                            OpenZeppelin Safe Pattern:\n\
                            ```solidity\n\
                            function recover(bytes32 hash, bytes memory signature) \n\
                                internal pure returns (address) \n\
                            {{\n\
                                (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);\n\
                                address signer = ecrecover(hash, v, r, s);\n\
                                \n\
                                require(signer != address(0), 'ECDSA: invalid signature');\n\
                                \n\
                                return signer;\n\
                            }}\n\
                            ```\n\
                            \n\
                            IMPACT:\n\
                            - Ronin Bridge: $625M stolen\n\
                            - Multiple other protocols: $50M+ cumulative\n\
                            - Complete authentication bypass\n\
                            - Irreversible fund loss\n\
                            \n\
                            FIX CHECKLIST:\n\
                            ✓ Always check ecrecover result != address(0)\n\
                            ✓ Never authorize address(0) as validator/signer\n\
                            ✓ Validate all addresses before adding to auth lists\n\
                            ✓ Use OpenZeppelin's ECDSA library (handles this)\n\
                            ✓ Add explicit tests for invalid signatures",
                            i
                        ),
                        location: i,
                        precompile_address: 0x01,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ ECRECOVER SIGNATURE MALLEABILITY ============
    
    fn detect_ecrecover_malleability(&self) -> Vec<PrecompileVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: ecrecover usage without checking s value range
        // Signature malleability: same message can have 2 valid signatures
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.is_call_to_ecrecover(i) {
                // Check if 's' value is validated (should be <= secp256k1n / 2)
                if !self.has_s_value_validation(i) {
                    vulnerabilities.push(PrecompileVulnerability {
                        vulnerability_type: PrecompileIssueType::EcrecoverSignatureMalleability,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "ecrecover signature malleability - s value not validated".to_string(),
                        exploit_scenario: format!(
                            "SIGNATURE MALLEABILITY at position {}:\n\
                            \n\
                            For every valid ECDSA signature (r, s), there exists another valid\n\
                            signature (r, -s mod n) for the same message and signer.\n\
                            \n\
                            Impact:\n\
                            - Replay protection bypass if based on signature hash\n\
                            - Nonce tracking issues\n\
                            - Front-running with modified signature\n\
                            \n\
                            Fix: Require s <= secp256k1n / 2 (EIP-2)\n\
                            ```solidity\n\
                            require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);\n\
                            ```",
                            i
                        ),
                        location: i,
                        precompile_address: 0x01,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ MODEXP DOS ============
    
    fn detect_modexp_dos(&self) -> Vec<PrecompileVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALL to address 0x05 (modexp) with unbounded exponent
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.is_call_to_modexp(i) {
                // Check if exponent size is bounded
                if !self.has_modexp_size_limit(i) {
                    vulnerabilities.push(PrecompileVulnerability {
                        vulnerability_type: PrecompileIssueType::ModexpDoS,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Unbounded modexp precompile call - DoS risk".to_string(),
                        exploit_scenario: format!(
                            "MODEXP DOS at position {}:\n\
                            \n\
                            Modular exponentiation with large exponents consumes massive gas.\n\
                            Attacker can provide huge exponent causing transaction to run out of gas.\n\
                            \n\
                            Attack: Call with exponent = 2^256 → millions of gas consumed\n\
                            \n\
                            Fix: Limit exponent size in bytes to reasonable value (e.g., 32 bytes)",
                            i
                        ),
                        location: i,
                        precompile_address: 0x05,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ BN256 INVALID CURVE POINTS ============
    
    fn detect_bn256_invalid_points(&self) -> Vec<PrecompileVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALL to 0x06/0x07/0x08 (BN256 precompiles) without point validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.is_call_to_bn256_precompile(i) {
                if !self.has_curve_point_validation(i) {
                    let precompile_addr = self.get_precompile_address(i);
                    vulnerabilities.push(PrecompileVulnerability {
                        vulnerability_type: PrecompileIssueType::InvalidCurvePoint,
                        severity: SecuritySeverity::High,
                        confidence: 0.65,
                        description: format!("BN256 precompile (0x{:02x}) without curve point validation", precompile_addr),
                        exploit_scenario: format!(
                            "BN256 INVALID CURVE POINT at position {}:\n\
                            \n\
                            BN256 operations (ecAdd, ecMul, pairing) accept invalid curve points.\n\
                            This can lead to:\n\
                            - ZK proof verification bypass\n\
                            - Consensus failures in L2s\n\
                            - Privacy protocol breaks\n\
                            \n\
                            Fix: Validate points are on curve before calling precompile",
                            i
                        ),
                        location: i,
                        precompile_address: precompile_addr,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn is_call_to_ecrecover(&self, pos: usize) -> bool {
        // Check if call target is 0x01 (ecrecover)
        // Look backwards for PUSH1 0x01
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && // PUSH1
               i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x01 { // Address 0x01
                return true;
            }
        }
        false
    }

    fn is_call_to_modexp(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x05 {
                return true;
            }
        }
        false
    }

    fn is_call_to_bn256_precompile(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                let addr = self.bytecode[i + 1];
                if addr == 0x06 || addr == 0x07 || addr == 0x08 {
                    return true;
                }
            }
        }
        false
    }

    fn get_precompile_address(&self, pos: usize) -> u8 {
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() {
                return self.bytecode[i + 1];
            }
        }
        0
    }

    fn has_zero_address_check_after(&self, pos: usize) -> bool {
        // Look for comparison with zero and revert/jumpi
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 4 < self.bytecode.len() {
                // Pattern: PUSH 0, EQ, ISZERO
                if self.bytecode[i] == 0x60 && self.bytecode[i+1] == 0x00 &&
                   self.bytecode[i+2] == 0x14 {
                    return true;
                }
            }
        }
        false
    }

    fn has_s_value_validation(&self, _pos: usize) -> bool {
        // Check for s value range validation (complex pattern)
        // For now, conservative - assume not validated
        false
    }

    fn has_modexp_size_limit(&self, _pos: usize) -> bool {
        // Check for bounds on exponent size
        // Complex to detect reliably in bytecode
        false
    }

    fn has_curve_point_validation(&self, _pos: usize) -> bool {
        // Check for curve point validation logic
        false
    }
}
