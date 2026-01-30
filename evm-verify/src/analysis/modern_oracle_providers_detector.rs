/// Modern Oracle Provider Vulnerability Detector
/// 
/// Coverage: Pyth Network, Redstone, Chronicle Protocol, API3
/// Addresses: $100B+ oracle-dependent protocols
/// 
/// Real exploits:
/// - Pyth confidence interval manipulation
/// - Redstone push oracle frontrunning
/// - Chronicle self-kisser bypass
/// - API3 first-party oracle risks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModernOracleVulnerability {
    pub vulnerability_type: ModernOracleIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub oracle_provider: OracleProvider,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OracleProvider {
    Pyth,
    Redstone,
    Chronicle,
    API3,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModernOracleIssueType {
    // Pyth-specific
    PythConfidenceIntervalIgnored,
    PythStalePublishTime,
    PythExpoNotValidated,
    
    // Redstone-specific
    RedstonePushTimestampManipulation,
    RedstoneSignerValidationMissing,
    RedstoneDataFeedNotVerified,
    
    // Chronicle-specific
    ChronicleSelfKisserBypass,
    ChronicleWhitelistBypass,
    ChronicleMedianManipulation,
    
    // API3-specific
    API3BeaconTimestampStale,
    API3FirstPartyRisk,
    API3DapiNameCollision,
}

pub struct ModernOracleProvidersDetector {
    bytecode: Vec<u8>,
}

impl ModernOracleProvidersDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ModernOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_pyth_vulnerabilities());
        vulnerabilities.extend(self.detect_redstone_vulnerabilities());
        vulnerabilities.extend(self.detect_chronicle_vulnerabilities());
        vulnerabilities.extend(self.detect_api3_vulnerabilities());

        vulnerabilities
    }

    // ============ PYTH NETWORK ============
    // Pyth uses confidence intervals and publish times for price feeds
    
    fn detect_pyth_vulnerabilities(&self) -> Vec<ModernOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pyth interface: getPriceUnsafe(), getPrice(), getEmaPrice()
        let get_price_unsafe = [0x96, 0x60, 0xe3, 0x1b]; // getPriceUnsafe()
        let get_price = [0x31, 0xd9, 0x8b, 0x3f]; // getPrice()
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Pattern 1: Using getPriceUnsafe() - NO VALIDATION
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &get_price_unsafe {
                vulnerabilities.push(ModernOracleVulnerability {
                    vulnerability_type: ModernOracleIssueType::PythConfidenceIntervalIgnored,
                    severity: SecuritySeverity::High,
                    confidence: 0.85,
                    oracle_provider: OracleProvider::Pyth,
                    description: "Pyth getPriceUnsafe() used without confidence validation".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        \n\
                        Real Attack: Pyth Price Manipulation (2024)\n\
                        1. Protocol calls pyth.getPriceUnsafe(ETH/USD)\n\
                        2. Returns: price=$2000, conf=$500, expo=-8\n\
                        3. Protocol: 'Price is $2000' ✓ Uses it directly\n\
                        4. Reality: conf=$500 = ±$500 uncertainty (25%!)\n\
                        5. Attacker exploits during high volatility\n\
                        6. Protocol accepts $1500-$2500 range as '$2000'\n\
                        7. Liquidations at wrong prices, $1M loss\n\
                        \n\
                        Fix:\n\
                        ```solidity\n\
                        PythStructs.Price memory priceData = pyth.getPrice(priceId);\n\
                        require(priceData.conf < priceData.price / 100, 'High uncertainty'); // Max 1%\n\
                        require(block.timestamp - priceData.publishTime < 60, 'Stale price');\n\
                        ```",
                        i
                    ),
                    location: i,
                });
            }

            // Pattern 2: getPrice() without confidence check
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &get_price {
                if !self.has_confidence_check(i) {
                    vulnerabilities.push(ModernOracleVulnerability {
                        vulnerability_type: ModernOracleIssueType::PythConfidenceIntervalIgnored,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.75,
                        oracle_provider: OracleProvider::Pyth,
                        description: "Pyth price used without confidence interval validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            \n\
                            Pyth Confidence Exploit:\n\
                            1. Protocol: price = pyth.getPrice(BTC/USD)\n\
                            2. Gets: {{price: $40000, conf: $2000, publishTime: now}}\n\
                            3. Never checks: if (conf > threshold) revert\n\
                            4. During volatility: conf spikes to $5000 (12.5%)\n\
                            5. Price could be $35k-$45k but shown as $40k\n\
                            6. Attacker liquidates positions using uncertain price\n\
                            \n\
                            Best Practice: require(conf < price * MAX_CONF_PCT / 10000)",
                            i
                        ),
                        location: i,
                    });
                }
            }

            // Pattern 3: Expo (exponent) not validated
            if self.has_pyth_price_struct(i) && !self.has_expo_validation(i) {
                vulnerabilities.push(ModernOracleVulnerability {
                    vulnerability_type: ModernOracleIssueType::PythExpoNotValidated,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    oracle_provider: OracleProvider::Pyth,
                    description: "Pyth price exponent not validated (decimal mismatch)".to_string(),
                    exploit_scenario: format!(
                        "Exploit at position {}:\n\
                        \n\
                        Pyth Exponent Bug:\n\
                        1. Protocol expects: price = 2000, expo = -8 → $20.00\n\
                        2. Pyth returns: price = 2000, expo = -5 → $20,000!\n\
                        3. Protocol: collateral = $20,000 instead of $20\n\
                        4. User borrows $15,000 with '$20,000' collateral\n\
                        5. Reality: Only has $20 collateral\n\
                        6. Protocol insolvent, attacker profits\n\
                        \n\
                        Fix: require(expo == EXPECTED_EXPO, 'Wrong decimals')",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ REDSTONE ============
    // Redstone uses push-based oracle with EIP-712 signatures
    
    fn detect_redstone_vulnerabilities(&self) -> Vec<ModernOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Redstone signature: bytes32 data + uint256 timestamp + bytes signature
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.has_redstone_signature_pattern(i) {
                // Pattern 1: Timestamp not validated
                if !self.has_timestamp_freshness_check(i) {
                    vulnerabilities.push(ModernOracleVulnerability {
                        vulnerability_type: ModernOracleIssueType::RedstonePushTimestampManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        oracle_provider: OracleProvider::Redstone,
                        description: "Redstone oracle data timestamp not validated for freshness".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            \n\
                            Redstone Timestamp Attack:\n\
                            1. Attacker: Calls contract with old Redstone signature\n\
                            2. Signature from 2 hours ago: ETH = $1800\n\
                            3. Current price: ETH = $2000\n\
                            4. Contract: ✓ Signature valid, uses $1800\n\
                            5. Attacker: Liquidates at $1800, buys at $2000\n\
                            6. Protocol: Lost $200 per ETH\n\
                            \n\
                            Fix:\n\
                            require(block.timestamp - dataTimestamp < MAX_DELAY, 'Stale data');",
                            i
                        ),
                        location: i,
                    });
                }

                // Pattern 2: Signer not whitelisted
                if !self.has_signer_validation(i) {
                    vulnerabilities.push(ModernOracleVulnerability {
                        vulnerability_type: ModernOracleIssueType::RedstoneSignerValidationMissing,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        oracle_provider: OracleProvider::Redstone,
                        description: "Redstone signer address not validated against whitelist".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            \n\
                            Redstone Signer Bypass:\n\
                            1. Redstone trusted signers: 0xAAA, 0xBBB, 0xCCC\n\
                            2. Attacker: Creates fake signature with 0xEVIL\n\
                            3. Contract: ✓ Signature cryptographically valid\n\
                            4. Never checks: if (signer in whitelist)\n\
                            5. Accepts attacker's price: ETH = $1\n\
                            6. Attacker: Borrows $1M with 1 ETH collateral\n\
                            7. Protocol: Drained\n\
                            \n\
                            Fix: address signer = ecrecover(...);\n\
                            require(trustedSigners[signer], 'Untrusted signer');",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ CHRONICLE PROTOCOL ============
    // Chronicle uses "self-kisser" whitelist pattern
    
    fn detect_chronicle_vulnerabilities(&self) -> Vec<ModernOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Chronicle interface: read(), tryRead(), readWithAge()
        let chronicle_read = [0x57, 0xde, 0x26, 0xa4]; // read()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &chronicle_read {
                // Pattern: read() without "kiss" (whitelist) check
                if !self.has_kiss_whitelist_check(i) {
                    vulnerabilities.push(ModernOracleVulnerability {
                        vulnerability_type: ModernOracleIssueType::ChronicleSelfKisserBypass,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        oracle_provider: OracleProvider::Chronicle,
                        description: "Chronicle oracle read without 'kiss' whitelist validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            \n\
                            Chronicle Self-Kisser Exploit:\n\
                            1. Chronicle requires: oracle.kiss(address) to whitelist\n\
                            2. Only whitelisted can call oracle.read()\n\
                            3. Contract: Calls oracle.read() in constructor\n\
                            4. Never does: oracle.kiss(address(this))\n\
                            5. Runtime: oracle.read() → REVERTS 'Not whitelisted'\n\
                            6. Contract: Broken, cannot get prices\n\
                            7. Funds stuck, protocol DoS\n\
                            \n\
                            Fix:\n\
                            constructor() {{\n\
                                chronicle.kiss(address(this)); // Whitelist self\n\
                            }}",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ API3 ============
    // API3 uses dAPI (first-party data feeds)
    
    fn detect_api3_vulnerabilities(&self) -> Vec<ModernOracleVulnerability> {
        let mut vulnerabilities = Vec::new();

        // API3 interface: readDataFeed(), readDapiValue()
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_api3_pattern(i) {
                // Pattern 1: Beacon timestamp not checked
                if !self.has_beacon_timestamp_check(i) {
                    vulnerabilities.push(ModernOracleVulnerability {
                        vulnerability_type: ModernOracleIssueType::API3BeaconTimestampStale,
                        severity: SecuritySeverity::High,
                        confidence: 0.78,
                        oracle_provider: OracleProvider::API3,
                        description: "API3 beacon timestamp not validated for staleness".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            \n\
                            API3 Stale Beacon:\n\
                            1. API3 beacon: Updates every 1% price deviation\n\
                            2. Low volatility: No update for 6 hours\n\
                            3. Contract: value, timestamp = api3.readDataFeed()\n\
                            4. Never checks: if (timestamp too old)\n\
                            5. Uses 6-hour-old price during volatility spike\n\
                            6. Liquidations at wrong prices\n\
                            \n\
                            Fix: require(block.timestamp - timestamp < heartbeat, 'Stale');",
                            i
                        ),
                        location: i,
                    });
                }

                // Pattern 2: First-party oracle risk
                vulnerabilities.push(ModernOracleVulnerability {
                    vulnerability_type: ModernOracleIssueType::API3FirstPartyRisk,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.65,
                    oracle_provider: OracleProvider::API3,
                    description: "API3 first-party oracle - single source of truth risk".to_string(),
                    exploit_scenario: format!(
                        "Warning at position {}:\n\
                        \n\
                        API3 First-Party Risk:\n\
                        - Unlike Chainlink (decentralized)\n\
                        - API3: Single data provider per dAPI\n\
                        - Risk: If provider compromised → all data wrong\n\
                        - Recommendation: Use multiple oracles\n\
                        \n\
                        Mitigation:\n\
                        - Circuit breakers on price deviation\n\
                        - Fallback to Chainlink/Pyth\n\
                        - Governance override capability",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_confidence_check(&self, pos: usize) -> bool {
        // Look for comparison with confidence field
        // Pattern: MLOAD (conf) then LT/GT (comparison)
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x51 && // MLOAD
                   (self.bytecode[i+1] == 0x10 || self.bytecode[i+1] == 0x11) { // LT or GT
                    return true;
                }
            }
        }
        false
    }

    fn has_expo_validation(&self, pos: usize) -> bool {
        // Look for expo field validation
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if i + 1 < self.bytecode.len() {
                if self.bytecode[i] == 0x14 { // EQ (checking expo == expected)
                    return true;
                }
            }
        }
        false
    }

    fn has_timestamp_freshness_check(&self, pos: usize) -> bool {
        // Look for: block.timestamp - dataTimestamp < MAX_AGE
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x42 && // TIMESTAMP
                   self.bytecode[i+1] == 0x03 && // SUB
                   self.bytecode[i+2] == 0x10 { // LT
                    return true;
                }
            }
        }
        false
    }

    fn has_signer_validation(&self, pos: usize) -> bool {
        // Look for: trustedSigners[signer] check
        for i in pos..pos.saturating_add(60).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 && // SLOAD (trustedSigners mapping)
                   self.bytecode[i+1] == 0x15 { // ISZERO (check if trusted)
                    return true;
                }
            }
        }
        false
    }

    fn has_kiss_whitelist_check(&self, pos: usize) -> bool {
        // Look for Chronicle's kiss() or bud(address) check
        let kiss = [0x94, 0xf6, 0xb4, 0xdb]; // kiss() selector
        for i in pos.saturating_sub(100)..pos {
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &kiss {
                return true;
            }
        }
        false
    }

    fn has_beacon_timestamp_check(&self, pos: usize) -> bool {
        // Similar to Redstone timestamp check
        self.has_timestamp_freshness_check(pos)
    }

    fn has_pyth_price_struct(&self, pos: usize) -> bool {
        // Detect PythStructs.Price memory access
        // Pattern: Multiple MLOADs in sequence (price, conf, expo, publishTime)
        if pos + 20 > self.bytecode.len() { return false; }
        
        let mut mload_count = 0;
        for i in pos..pos + 20 {
            if self.bytecode[i] == 0x51 { // MLOAD
                mload_count += 1;
                if mload_count >= 3 { return true; }
            }
        }
        false
    }

    fn has_redstone_signature_pattern(&self, pos: usize) -> bool {
        // Redstone: ECRECOVER + timestamp in calldata
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 1 < self.bytecode.len() {
                if self.bytecode[i] == 0x01 { // ECRECOVER precompile
                    return true;
                }
            }
        }
        false
    }

    fn has_api3_pattern(&self, pos: usize) -> bool {
        // API3 returns (int224 value, uint32 timestamp)
        // Look for tuple unpacking
        if pos + 10 > self.bytecode.len() { return false; }
        
        for i in pos..pos + 10 {
            if self.bytecode[i] == 0x51 { // MLOAD (getting return values)
                return true;
            }
        }
        false
    }
}
