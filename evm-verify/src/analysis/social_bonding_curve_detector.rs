/// Social Token Bonding Curve Vulnerability Detector
/// 
/// Coverage: Friend.tech, Blast Gold, Stars Arena, New Bitcoin City
/// Market Size: $500M+ social token trading
/// 
/// Attack vectors:
/// - First buyer advantage (MEV)
/// - Bonding curve manipulation
/// - Supply control exploits
/// - Fee extraction loops
/// - Price oracle manipulation
/// 
/// Real exploits:
/// - Friend.tech: $20M TVL attacks
/// - Stars Arena: $3M exploit (Oct 2023)
/// - Blast Gold: Points manipulation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialBondingCurveVulnerability {
    pub vulnerability_type: BondingCurveIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BondingCurveIssueType {
    FirstBuyerAdvantage,           // First buyer gets unfair price
    BondingCurveManipulation,      // Attacker manipulates curve
    SupplyInflationAttack,         // Supply can be inflated
    FeeExtractionLoop,             // Fees extracted in cycles
    PriceOracleManipulation,       // Price calculation exploitable
    ProtocolFeeBypass,             // Fee mechanism bypassed
    KeyTransferExploit,            // Key ownership transfer issues
    CircularTradingProfit,         // Circular trading for profit
    ZeroSupplyDivision,            // Division by zero on no supply
    RoundingExploitation,          // Rounding errors amplified
}

pub struct SocialBondingCurveDetector {
    bytecode: Vec<u8>,
}

impl SocialBondingCurveDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_bonding_curve_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_first_buyer_issues());
        vulnerabilities.extend(self.detect_curve_manipulation());
        vulnerabilities.extend(self.detect_supply_attacks());
        vulnerabilities.extend(self.detect_fee_exploits());
        vulnerabilities.extend(self.detect_price_manipulation());

        vulnerabilities
    }

    // ============ FIRST BUYER ADVANTAGE ============
    // Critical in Friend.tech: First buyer gets best price, MEV opportunity
    
    fn detect_first_buyer_issues(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Price calculation based on supply
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_price_calculation(i) {
                // Check if first buy gets special treatment
                if !self.has_first_buy_protection(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::FirstBuyerAdvantage,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "First buyer gets disproportionate advantage (MEV extractable)".to_string(),
                        exploit_scenario: format!(
                            "FIRST BUYER MEV at position {}:\n\
                            \n\
                            Friend.tech Pattern:\n\
                            ```solidity\n\
                            // Price formula: supply^2 / 16000\n\
                            function buyKeys(address subject) {{\n\
                                uint supply = keysSupply[subject];\n\
                                uint price = supply ** 2 / 16000;\n\
                                // First key: supply=0 → price=0\n\
                                // Second key: supply=1 → price=1/16000 ETH\n\
                            }}\n\
                            ```\n\
                            \n\
                            Exploit (Real Friend.tech MEV):\n\
                            1. Creator: Announces new profile\n\
                            2. MEV Bot: Detects transaction in mempool\n\
                            3. Bot: Frontruns with massive gas\n\
                            4. Bot: Buys first key for ~0 ETH\n\
                            5. Other users: Buy at 1/16000, 4/16000, 9/16000...\n\
                            6. Bot: Sells at peak price\n\
                            7. Profit: $1000+ per profile\n\
                            \n\
                            Impact:\n\
                            - Creators lose value\n\
                            - Early supporters priced out\n\
                            - Pure MEV extraction\n\
                            \n\
                            Mitigation:\n\
                            - First key reserved for creator\n\
                            - Minimum first key price\n\
                            - Commit-reveal for first buy",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ CURVE MANIPULATION ============
    
    fn detect_curve_manipulation(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Supply-based pricing without safeguards
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.has_quadratic_pricing(i) {
                // Check for manipulation vectors
                if !self.has_price_bounds(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::BondingCurveManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Bonding curve can be manipulated via supply control".to_string(),
                        exploit_scenario: format!(
                            "CURVE MANIPULATION at position {}:\n\
                            \n\
                            Attack Vector:\n\
                            1. Bonding curve: price = supply^2\n\
                            2. Attacker: Buys 100 keys (supply=100)\n\
                            3. Price now: 10,000 units\n\
                            4. Victim: Buys 1 key at inflated price\n\
                            5. Attacker: Sells all 100 keys\n\
                            6. Profit: Price inflation × 100\n\
                            \n\
                            Stars Arena Exploit (Oct 2023):\n\
                            - Attacker controlled supply\n\
                            - Manipulated price curve\n\
                            - $3M drained\n\
                            \n\
                            Mitigation:\n\
                            - Max price bounds\n\
                            - Slippage limits\n\
                            - Time-weighted pricing",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for zero division
                if !self.has_zero_supply_check(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::ZeroSupplyDivision,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.85,
                        description: "Price calculation may divide by zero when supply is zero".to_string(),
                        exploit_scenario: format!(
                            "DIVISION BY ZERO at position {}:\n\
                            \n\
                            Bug:\n\
                            ```solidity\n\
                            uint price = reserve / supply;  // supply can be 0!\n\
                            ```\n\
                            \n\
                            Causes contract to revert or return MAX_UINT",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ SUPPLY ATTACKS ============
    
    fn detect_supply_attacks(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Unrestricted supply minting
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_supply_increase(i) {
                if !self.has_supply_cap(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::SupplyInflationAttack,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.70,
                        description: "Supply can be inflated without cap, devaluing existing keys".to_string(),
                        exploit_scenario: format!(
                            "SUPPLY INFLATION at position {}:\n\
                            \n\
                            Attack:\n\
                            1. Legitimate users: Hold 100 keys\n\
                            2. Value: 100 * price\n\
                            3. Attacker: Finds supply mint bug\n\
                            4. Mints: 1,000,000 keys\n\
                            5. Supply: 1,000,100 total\n\
                            6. Original keys: Worth 0.01% of before\n\
                            7. Attacker: Sells at inflated total value\n\
                            \n\
                            Similar to:\n\
                            - Token supply exploits\n\
                            - Share dilution\n\
                            \n\
                            Fix: Hard cap on supply per subject",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ FEE EXPLOITS ============
    
    fn detect_fee_exploits(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Fee calculation based on trade amount
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_fee_calculation(i) {
                // Check for fee extraction loops
                if self.has_circular_trading_pattern(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::CircularTradingProfit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "Circular trading can extract value via fees".to_string(),
                        exploit_scenario: format!(
                            "CIRCULAR TRADING at position {}:\n\
                            \n\
                            Friend.tech Fee Structure:\n\
                            - 5% protocol fee\n\
                            - 5% subject fee (key holder)\n\
                            \n\
                            Exploit:\n\
                            1. Alice holds Alice's keys (100%)\n\
                            2. Bob: Buys Alice's key for 1 ETH\n\
                            3. Fee: 0.1 ETH → Alice\n\
                            4. Bob: Sells key back\n\
                            5. Fee: 0.09 ETH → Alice again\n\
                            6. Repeat 100 times\n\
                            7. Alice: Extracted fees from Bob's trading\n\
                            \n\
                            Issue: Self-trading or coordinated trading\n\
                            \n\
                            Mitigation:\n\
                            - Minimum hold time\n\
                            - Trade frequency limits\n\
                            - Anti-wash trading",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for fee bypass
                if !self.has_fee_enforcement(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::ProtocolFeeBypass,
                        severity: SecuritySeverity::High,
                        confidence: 0.72,
                        description: "Protocol fees can be bypassed via alternative paths".to_string(),
                        exploit_scenario: format!(
                            "FEE BYPASS at position {}:\n\
                            \n\
                            Pattern:\n\
                            - buyKeys() charges 10% fee\n\
                            - transferKeys() charges 0% fee\n\
                            \n\
                            Exploit:\n\
                            1. Attacker: Creates helper contract\n\
                            2. Helper: Buys keys at 10% fee\n\
                            3. Helper: Transfers to attacker (0% fee)\n\
                            4. Attacker: Trades via transfers\n\
                            5. Protocol: Loses 10% fee revenue\n\
                            \n\
                            Fix: Charge fee on all ownership changes",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ PRICE MANIPULATION ============
    
    fn detect_price_manipulation(&self) -> Vec<SocialBondingCurveVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Price oracle or calculation
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.has_get_price_function(i) {
                // Check for rounding errors
                if self.has_division_before_multiplication(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::RoundingExploitation,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.68,
                        description: "Price rounding errors can be exploited at scale".to_string(),
                        exploit_scenario: format!(
                            "ROUNDING EXPLOIT at position {}:\n\
                            \n\
                            Issue:\n\
                            ```solidity\n\
                            uint price = (supply ** 2) / 16000;  // Integer division\n\
                            ```\n\
                            \n\
                            Exploit:\n\
                            - supply=126: price = 15876/16000 = 0 (rounds down)\n\
                            - supply=127: price = 16129/16000 = 1\n\
                            \n\
                            Attack:\n\
                            1. Buy at supply=126 for price=0\n\
                            2. Sell at supply=127 for price=1\n\
                            3. Repeat 1000 times\n\
                            4. Profit from rounding\n\
                            \n\
                            Mitigation:\n\
                            - Use higher precision\n\
                            - Minimum price floor\n\
                            - Fixed-point math library",
                            i
                        ),
                        location: i,
                    });
                }

                // Check for price oracle manipulation
                if !self.has_price_sanity_check(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::PriceOracleManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: "Price calculation lacks sanity checks (min/max bounds)".to_string(),
                        exploit_scenario: format!(
                            "PRICE BOUNDS at position {}:\n\
                            \n\
                            Missing:\n\
                            - Minimum price (prevent free keys)\n\
                            - Maximum price (prevent griefing)\n\
                            - Rate of change limit\n\
                            \n\
                            Without bounds:\n\
                            - Price can go to 0 or infinity\n\
                            - Users get rekt by extreme prices\n\
                            - Protocol becomes unusable",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        // Pattern: Key transfer without fee
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_transfer_function(i) {
                if !self.has_transfer_fee(i) {
                    vulnerabilities.push(SocialBondingCurveVulnerability {
                        vulnerability_type: BondingCurveIssueType::KeyTransferExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.65,
                        description: "Key transfers bypass trading fees and bonding curve".to_string(),
                        exploit_scenario: format!(
                            "KEY TRANSFER BYPASS at position {}:\n\
                            \n\
                            Issue: Direct transfers skip bonding curve.\n\
                            \n\
                            Exploit:\n\
                            1. Buy key via bonding curve: pay 1 ETH + fees\n\
                            2. Transfer key to another address: free\n\
                            3. Recipient can sell via curve\n\
                            4. Bypasses protocol fee collection\n\
                            \n\
                            Alternative:\n\
                            - OTC markets emerge\n\
                            - Protocol loses fee revenue\n\
                            - Price discovery breaks\n\
                            \n\
                            Consider:\n\
                            - Disable transfers OR\n\
                            - Charge fee on transfers OR\n\
                            - Update supply tracking",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn is_bonding_curve_contract(&self) -> bool {
        // Bonding curve contracts have:
        // 1. Buy/sell functions
        // 2. Supply tracking
        // 3. Price calculation based on supply
        
        let buy = [0x62, 0x75, 0x79, 0x4b]; // "buyK" (buyKeys)
        let sell = [0x73, 0x65, 0x6c, 0x6c]; // "sell"
        
        let has_buy = self.bytecode.windows(4).any(|w| w == buy);
        let has_sell = self.bytecode.windows(4).any(|w| w == sell);
        let has_supply = self.bytecode.windows(10).any(|w| {
            // Supply tracking: SLOAD + ADD/SUB + SSTORE
            w.contains(&0x54) && (w.contains(&0x01) || w.contains(&0x03)) && w.contains(&0x55)
        });
        
        has_buy && has_sell && has_supply
    }

    fn has_price_calculation(&self, pos: usize) -> bool {
        // Price = f(supply), involves supply SLOAD + math
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 5 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 &&      // SLOAD (supply)
                   (self.bytecode[i+2] == 0x02 ||  // MUL
                    self.bytecode[i+2] == 0x0A) {   // EXP (power)
                    return true;
                }
            }
        }
        false
    }

    fn has_first_buy_protection(&self, pos: usize) -> bool {
        // Check if supply==0 handled specially
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x15 &&      // ISZERO (supply == 0)
                   self.bytecode[i+1] == 0x57 {     // JUMPI (special case)
                    return true;
                }
            }
        }
        false
    }

    fn has_quadratic_pricing(&self, pos: usize) -> bool {
        // Quadratic: supply^2 or similar
        for i in pos..pos.saturating_add(25).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                // Pattern: DUP + MUL (x^2) or EXP with 2
                if (self.bytecode[i] == 0x80 && self.bytecode[i+1] == 0x02) || // DUP1, MUL
                   (self.bytecode[i] == 0x0A && self.bytecode[i-1] == 0x60 && self.bytecode[i-2] == 0x02) { // PUSH1 2, EXP
                    return true;
                }
            }
        }
        false
    }

    fn has_price_bounds(&self, pos: usize) -> bool {
        // Min/max price checks
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                // LT/GT + REVERT (bounds check)
                if (self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11) &&
                   self.bytecode[i+2] == 0xFD {
                    return true;
                }
            }
        }
        false
    }

    fn has_zero_supply_check(&self, pos: usize) -> bool {
        // Check for supply == 0 before division
        for i in pos.saturating_sub(15)..pos {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x15 {      // ISZERO
                    return true;
                }
            }
        }
        false
    }

    fn has_supply_increase(&self, pos: usize) -> bool {
        // SLOAD + ADD + SSTORE (supply++)
        if pos + 10 > self.bytecode.len() { return false; }
        
        for i in pos..pos+10 {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 &&      // SLOAD
                   self.bytecode[i+1] == 0x01 &&    // ADD
                   self.bytecode[i+2] == 0x55 {     // SSTORE
                    return true;
                }
            }
        }
        false
    }

    fn has_supply_cap(&self, pos: usize) -> bool {
        // Max supply check: supply < MAX
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x10 {      // LT (less than max)
                    return true;
                }
            }
        }
        false
    }

    fn has_fee_calculation(&self, pos: usize) -> bool {
        // Fee = amount * percentage / 100
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x02 &&      // MUL (amount * %)
                   self.bytecode[i+2] == 0x04 {     // DIV (/ 100)
                    return true;
                }
            }
        }
        false
    }

    fn has_circular_trading_pattern(&self, pos: usize) -> bool {
        // Heuristic: Multiple buy/sell in same transaction
        // Would need transaction trace analysis in reality
        false // Cannot detect from bytecode alone
    }

    fn has_fee_enforcement(&self, pos: usize) -> bool {
        // Fee deduction before transfer
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 5 < self.bytecode.len() {
                if self.bytecode[i] == 0x03 &&      // SUB (amount - fee)
                   self.bytecode[i+3] == 0xF1 {     // CALL (transfer)
                    return true;
                }
            }
        }
        false
    }

    fn has_get_price_function(&self, pos: usize) -> bool {
        // Price getter function
        self.has_price_calculation(pos)
    }

    fn has_division_before_multiplication(&self, pos: usize) -> bool {
        // Anti-pattern: a / b * c (loses precision)
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x04 &&      // DIV
                   self.bytecode[i+1] == 0x02 {     // MUL
                    return true;
                }
            }
        }
        false
    }

    fn has_price_sanity_check(&self, pos: usize) -> bool {
        self.has_price_bounds(pos)
    }

    fn has_transfer_function(&self, pos: usize) -> bool {
        // Transfer = ownership change without buy/sell
        let transfer = [0x74, 0x72, 0x61, 0x6e]; // "tran" (transfer)
        
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &transfer {
                return true;
            }
        }
        false
    }

    fn has_transfer_fee(&self, pos: usize) -> bool {
        // Fee charged on transfer
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.has_fee_calculation(i) {
                return true;
            }
        }
        false
    }
}
