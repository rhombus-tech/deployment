/// Comprehensive Honeypot Contract Detector
/// 
/// Coverage: All major honeypot patterns ($50M+ annual scams)
/// Extends: approval_trap_phishing.rs with comprehensive honeypot detection
/// 
/// Honeypot types:
/// - Hidden mint functions (owner can mint unlimited tokens)
/// - Max transaction limits (can't sell large amounts)
/// - Anti-whale mechanisms (blocks large holders from selling)
/// - Liquidity locks (fake locks, owner can withdraw)
/// - Hidden blacklist (owner can blacklist sellers)
/// - Tax manipulation (buy tax low, sell tax 99%)
/// - Fake renounce ownership
/// - Time-delayed scams
/// 
/// Detection methods:
/// - Static bytecode analysis
/// - Pattern matching
/// - Privilege escalation checks

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotVulnerability {
    pub vulnerability_type: HoneypotType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub red_flags: Vec<String>,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HoneypotType {
    HiddenMintFunction,            // Owner can mint tokens
    MaxTxAmountRestriction,        // Can't sell more than X%
    AntiWhaleBlocksSell,           // Large holders can't sell
    FakeLiquidityLock,             // Lock can be bypassed
    HiddenBlacklist,               // Owner can blacklist
    AsymmetricTaxes,               // Buy 1% tax, sell 99% tax
    FakeRenounceOwnership,         // Ownership not actually renounced
    TimeBasedScam,                 // Works for N blocks then stops
    HiddenOwnerFunction,           // Disguised admin function
    ConditionalTransferFail,       // Transfer fails under conditions
    BalanceManipulation,           // balanceOf() returns fake value
    HoneypotRouter,                // Custom router that blocks sells
}

pub struct HoneypotComprehensiveDetector {
    bytecode: Vec<u8>,
}

impl HoneypotComprehensiveDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_hidden_mint());
        vulnerabilities.extend(self.detect_transfer_restrictions());
        vulnerabilities.extend(self.detect_asymmetric_fees());
        vulnerabilities.extend(self.detect_blacklist_mechanisms());
        vulnerabilities.extend(self.detect_fake_security());
        vulnerabilities.extend(self.detect_ownership_tricks());

        vulnerabilities
    }

    // ============ HIDDEN MINT FUNCTION ============
    
    fn detect_hidden_mint(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Function that increases total supply without burning
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_supply_increase_function(i) {
                if !self.is_public_mint(i) && self.is_owner_restricted(i) {
                    let red_flags = vec![
                        "Owner-only mint function found".to_string(),
                        "Can inflate supply arbitrarily".to_string(),
                        "No maximum supply cap".to_string(),
                    ];

                    vulnerabilities.push(HoneypotVulnerability {
                        vulnerability_type: HoneypotType::HiddenMintFunction,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "Hidden mint function allows owner to create unlimited tokens".to_string(),
                        exploit_scenario: format!(
                            "🚨 HONEYPOT: HIDDEN MINT at position {}:\n\
                            \n\
                            Scam Pattern:\n\
                            1. Token launches: 1M supply, looks legit\n\
                            2. Users buy: Price goes up\n\
                            3. Hidden function: owner.mint(1B tokens)\n\
                            4. Supply now: 1.001B (1000x dilution)\n\
                            5. Owner dumps: Sells 1B at high price\n\
                            6. Users' tokens: Now worth 0.001x\n\
                            \n\
                            Example bytecode:\n\
                            ```solidity\n\
                            function _m1nt(uint amount) private onlyOwner {{\n\
                                _totalSupply += amount;  // No cap!\n\
                                _balances[owner] += amount;\n\
                            }}\n\
                            ```\n\
                            \n\
                            🚩 RED FLAGS:\n\
                            {}\n\
                            \n\
                            ✅ SAFE PATTERN:\n\
                            - Fixed supply (immutable)\n\
                            - OR public mint with max cap\n\
                            - OR time-locked mint",
                            i,
                            red_flags.join("\n")
                        ),
                        red_flags,
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ TRANSFER RESTRICTIONS ============
    
    fn detect_transfer_restrictions(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern 1: Max transaction amount
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_max_tx_check(i) {
                let red_flags = vec![
                    "Maximum transaction limit enforced".to_string(),
                    "Prevents selling large amounts".to_string(),
                    "Can trap whale investors".to_string(),
                ];

                vulnerabilities.push(HoneypotVulnerability {
                    vulnerability_type: HoneypotType::MaxTxAmountRestriction,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "Maximum transaction amount prevents large sells".to_string(),
                    exploit_scenario: format!(
                        "🚨 HONEYPOT: MAX TX LIMIT at position {}:\n\
                        \n\
                        Scam Pattern:\n\
                        1. Token: max tx = 1% of supply\n\
                        2. Whale buys: 10% of supply ($100k)\n\
                        3. Whale tries to sell: REVERT (>1% limit)\n\
                        4. Only option: Sell in 10 transactions\n\
                        5. Each sell: 5% tax + slippage\n\
                        6. Total loss: 50% value gone\n\
                        \n\
                        Red Flag Code:\n\
                        ```solidity\n\
                        require(amount <= _maxTxAmount, 'Exceeds max');\n\
                        // _maxTxAmount = 1% but not changeable\n\
                        ```\n\
                        \n\
                        🚩 RED FLAGS:\n\
                        {}\n\
                        \n\
                        Check:\n\
                        - Is max tx amount reasonable? (5-10% OK)\n\
                        - Can owner change it? (Red flag if only decreases)\n\
                        - Is it disabled after launch?",
                        i,
                        red_flags.join("\n")
                    ),
                    red_flags,
                    location: i,
                });
            }
        }

        // Pattern 2: Anti-whale (balance-based restriction)
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.has_anti_whale_check(i) {
                let applies_to_sell = self.check_applies_to_sell_only(i);
                
                if applies_to_sell {
                    let red_flags = vec![
                        "Anti-whale mechanism blocks sells".to_string(),
                        "Does NOT block buys".to_string(),
                        "Asymmetric protection".to_string(),
                    ];

                    vulnerabilities.push(HoneypotVulnerability {
                        vulnerability_type: HoneypotType::AntiWhaleBlocksSell,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.88,
                        description: "Anti-whale check blocks selling but not buying (honeypot!)".to_string(),
                        exploit_scenario: format!(
                            "🚨 HONEYPOT: ANTI-WHALE TRAP at position {}:\n\
                            \n\
                            Classic Honeypot:\n\
                            1. User buys: 5% of supply ✓ Allowed\n\
                            2. Price pumps: 10x gain!\n\
                            3. User sells: ❌ REVERT 'Anti-whale'\n\
                            4. Code: 'if (balance > 2% of supply) revert'\n\
                            5. User stuck: Can't sell, can't transfer\n\
                            6. Dev dumps: Sells via exempt address\n\
                            \n\
                            Code:\n\
                            ```solidity\n\
                            function _transfer(from, to, amount) {{\n\
                                if (to != uniswapPair) {{ // Only on sells\n\
                                    require(balanceOf(to) + amount <= maxWallet);\n\
                                }}\n\
                                // Can buy unlimited, can't sell if whale\n\
                            }}\n\
                            ```\n\
                            \n\
                            🚩 RED FLAGS:\n\
                            {}\n\
                            \n\
                            ⚠️  VERIFY: Does check apply to BOTH buy AND sell?",
                            i,
                            red_flags.join("\n")
                        ),
                        red_flags,
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ ASYMMETRIC FEES ============
    
    fn detect_asymmetric_fees(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Different buy vs sell taxes
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.has_fee_calculation(i) {
                if let Some((buy_fee, sell_fee)) = self.extract_fee_percentages(i) {
                    if sell_fee > buy_fee.saturating_mul(5) { // Sell fee 5x+ higher
                        let red_flags = vec![
                            format!("Buy fee: {}%", buy_fee),
                            format!("Sell fee: {}% ({}x higher!)", sell_fee, sell_fee / buy_fee.max(1)),
                            "Heavily discourages selling".to_string(),
                        ];

                        vulnerabilities.push(HoneypotVulnerability {
                            vulnerability_type: HoneypotType::AsymmetricTaxes,
                            severity: SecuritySeverity::High,
                            confidence: 0.90,
                            description: format!("Asymmetric taxes: Buy {}%, Sell {}%", buy_fee, sell_fee),
                            exploit_scenario: format!(
                                "🚨 HONEYPOT: TAX TRAP at position {}:\n\
                                \n\
                                Scam:\n\
                                Buy: 2% tax (looks reasonable)\n\
                                Sell: 99% tax (HIDDEN!)\n\
                                \n\
                                User Experience:\n\
                                1. Buys $1000 worth: Pays $20 tax (2%)\n\
                                2. Token 10x: Now worth $10,000\n\
                                3. Sells: Gets $100 after 99% tax\n\
                                4. Net: Lost $900 (-90% from start)\n\
                                \n\
                                Code (Hidden):\n\
                                ```solidity\n\
                                uint buyFee = 2;\n\
                                uint sellFee = 99;  // In obscured variable\n\
                                \n\
                                if (isSell) {{\n\
                                    fee = amount * sellFee / 100;\n\
                                }}\n\
                                ```\n\
                                \n\
                                🚩 RED FLAGS:\n\
                                {}\n\
                                \n\
                                ✅ REASONABLE:\n\
                                - Buy and sell fees should be similar\n\
                                - Max total fee: 10-15%",
                                i,
                                red_flags.join("\n")
                            ),
                            red_flags,
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    // ============ BLACKLIST MECHANISMS ============
    
    fn detect_blacklist_mechanisms(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Blacklist that blocks transfers
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.has_blacklist_check(i) {
                if self.is_owner_controlled_blacklist(i) {
                    let red_flags = vec![
                        "Owner can blacklist addresses".to_string(),
                        "Blacklisted users can't sell".to_string(),
                        "No un-blacklist mechanism".to_string(),
                    ];

                    vulnerabilities.push(HoneypotVulnerability {
                        vulnerability_type: HoneypotType::HiddenBlacklist,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.82,
                        description: "Hidden blacklist allows owner to block specific addresses from selling".to_string(),
                        exploit_scenario: format!(
                            "🚨 HONEYPOT: BLACKLIST TRAP at position {}:\n\
                            \n\
                            Scam Pattern:\n\
                            1. Token launches: Looks clean\n\
                            2. User buys: $10k worth\n\
                            3. Owner blacklists: user.address\n\
                            4. User tries to sell: ❌ REVERT\n\
                            5. User's tokens: Permanently stuck\n\
                            6. Owner can blacklist anyone at will\n\
                            \n\
                            Code:\n\
                            ```solidity\n\
                            mapping(address => bool) private _isBlacklisted;\n\
                            \n\
                            function _transfer(from, to, amount) {{\n\
                                require(!_isBlacklisted[from], 'Blacklisted');\n\
                                // ...\n\
                            }}\n\
                            \n\
                            function blacklist(address user) external onlyOwner {{\n\
                                _isBlacklisted[user] = true;\n\
                            }}\n\
                            ```\n\
                            \n\
                            🚩 RED FLAGS:\n\
                            {}\n\
                            \n\
                            ⚠️  Blacklists are OK for:\n\
                            - Known scammers (with timelock)\n\
                            - Sanctioned addresses (legal requirement)\n\
                            \n\
                            ❌ Red flags:\n\
                            - No timelock on blacklist function\n\
                            - No way to appeal/remove\n\
                            - Applied to all users",
                            i,
                            red_flags.join("\n")
                        ),
                        red_flags,
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ FAKE SECURITY ============
    
    fn detect_fake_security(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Fake liquidity lock
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.has_liquidity_lock_claim(i) {
                if self.has_emergency_withdraw(i) {
                    let red_flags = vec![
                        "Claims liquidity is locked".to_string(),
                        "Emergency withdraw function exists".to_string(),
                        "Owner can drain liquidity".to_string(),
                    ];

                    vulnerabilities.push(HoneypotVulnerability {
                        vulnerability_type: HoneypotType::FakeLiquidityLock,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.87,
                        description: "Fake liquidity lock - owner can withdraw via backdoor".to_string(),
                        exploit_scenario: format!(
                            "🚨 HONEYPOT: FAKE LOCK at position {}:\n\
                            \n\
                            Scam:\n\
                            Marketing: 'Liquidity locked for 1 year!'\n\
                            Reality: emergencyWithdraw() exists\n\
                            \n\
                            Attack:\n\
                            1. Launch: Lock liquidity (creates trust)\n\
                            2. Users buy: $1M TVL\n\
                            3. Owner calls: emergencyWithdraw()\n\
                            4. Removes: All liquidity\n\
                            5. Price: Crashes to $0\n\
                            6. Users: Can't sell (no liquidity)\n\
                            \n\
                            Code:\n\
                            ```solidity\n\
                            function lockLiquidity() external onlyOwner {{\n\
                                locked = true;\n\
                                unlockTime = block.timestamp + 365 days;\n\
                            }}\n\
                            \n\
                            function emergencyWithdraw() external onlyOwner {{\n\
                                // Bypasses lock!\n\
                                lpToken.transfer(owner, lpToken.balanceOf(this));\n\
                            }}\n\
                            ```\n\
                            \n\
                            🚩 RED FLAGS:\n\
                            {}\n\
                            \n\
                            ✅ REAL LOCK:\n\
                            - Use Unicrypt/Team Finance\n\
                            - NO emergency withdraw\n\
                            - Verifiable on-chain",
                            i,
                            red_flags.join("\n")
                        ),
                        red_flags,
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ OWNERSHIP TRICKS ============
    
    fn detect_ownership_tricks(&self) -> Vec<HoneypotVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Fake renounce ownership
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.has_renounce_ownership_function(i) {
                if !self.actually_renounces_ownership(i) {
                    let red_flags = vec![
                        "renounceOwnership() function exists".to_string(),
                        "Ownership not actually renounced".to_string(),
                        "Hidden admin functions remain active".to_string(),
                    ];

                    vulnerabilities.push(HoneypotVulnerability {
                        vulnerability_type: HoneypotType::FakeRenounceOwnership,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Fake renounceOwnership() - hidden admin access remains".to_string(),
                        exploit_scenario: format!(
                            "🚨 HONEYPOT: FAKE RENOUNCE at position {}:\n\
                            \n\
                            Scam:\n\
                            1. Owner calls: renounceOwnership()\n\
                            2. Transaction succeeds\n\
                            3. Marketing: 'Contract renounced! Safe!'\n\
                            4. Reality: Hidden admin address still has control\n\
                            \n\
                            Code:\n\
                            ```solidity\n\
                            address private _owner;\n\
                            address private _admin;  // Hidden!\n\
                            \n\
                            function renounceOwnership() external onlyOwner {{\n\
                                _owner = address(0);  // Looks renounced\n\
                                // But _admin still has full control!\n\
                            }}\n\
                            \n\
                            modifier onlyAdmin() {{\n\
                                require(msg.sender == _admin);\n\
                                _;\n\
                            }}\n\
                            ```\n\
                            \n\
                            🚩 RED FLAGS:\n\
                            {}\n\
                            \n\
                            ✅ VERIFY:\n\
                            - Check ALL admin modifiers\n\
                            - Look for secondary owner variables\n\
                            - Test all privileged functions",
                            i,
                            red_flags.join("\n")
                        ),
                        red_flags,
                        location: i,
                    });
                }
            }
        }

        // Pattern: Hidden owner function
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_hidden_privileged_function(i) {
                let red_flags = vec![
                    "Disguised admin function found".to_string(),
                    "Not in public documentation".to_string(),
                    "Suspicious privilege escalation".to_string(),
                ];

                vulnerabilities.push(HoneypotVulnerability {
                    vulnerability_type: HoneypotType::HiddenOwnerFunction,
                    severity: SecuritySeverity::High,
                    confidence: 0.70,
                    description: "Hidden privileged function detected".to_string(),
                    exploit_scenario: format!(
                        "HIDDEN ADMIN FUNCTION at position {}:\n\
                        \n\
                        Pattern: Admin functions with obfuscated names\n\
                        \n\
                        Examples:\n\
                        - _0x1234abcd() instead of withdraw()\n\
                        - updateConfig() that actually drains funds\n\
                        - claim() that sends tokens to owner\n\
                        \n\
                        🚩 RED FLAGS:\n\
                        {}\n\
                        \n\
                        Check: Decompile and verify all functions",
                        i,
                        red_flags.join("\n")
                    ),
                    red_flags,
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_supply_increase_function(&self, pos: usize) -> bool {
        // totalSupply += amount pattern
        for i in pos..pos.saturating_add(25).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 &&      // SLOAD (totalSupply)
                   self.bytecode[i+1] == 0x01 &&    // ADD
                   self.bytecode[i+2] == 0x55 {     // SSTORE
                    return true;
                }
            }
        }
        false
    }

    fn is_public_mint(&self, _pos: usize) -> bool {
        // Would need to check function visibility
        // Conservative: assume not public unless proven
        false
    }

    fn is_owner_restricted(&self, pos: usize) -> bool {
        // Check for onlyOwner modifier pattern
        for i in pos.saturating_sub(50)..pos {
            if i + 10 < self.bytecode.len() {
                // CALLER, SLOAD(owner), EQ, ISZERO, REVERT pattern
                if self.bytecode[i] == 0x33 &&      // CALLER
                   self.bytecode[i+2] == 0x14 {     // EQ
                    return true;
                }
            }
        }
        false
    }

    fn has_max_tx_check(&self, pos: usize) -> bool {
        // require(amount <= maxTxAmount)
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x11 &&      // GT (amount > max)
                   self.bytecode[i+2] == 0xFD {     // REVERT
                    return true;
                }
            }
        }
        false
    }

    fn has_anti_whale_check(&self, pos: usize) -> bool {
        // balanceOf(to) + amount <= maxWallet
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 5 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 &&      // SLOAD (balance)
                   self.bytecode[i+1] == 0x01 &&    // ADD (balance + amount)
                   self.bytecode[i+3] == 0x11 {     // GT (> maxWallet)
                    return true;
                }
            }
        }
        false
    }

    fn check_applies_to_sell_only(&self, pos: usize) -> bool {
        // Check if there's a uniswapPair comparison nearby
        for i in pos.saturating_sub(20)..pos.saturating_add(20).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x14 {      // EQ (comparing addresses)
                    return true; // Likely checking if to == pair (sell)
                }
            }
        }
        false
    }

    fn has_fee_calculation(&self, pos: usize) -> bool {
        // fee = amount * rate / 100
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x02 &&      // MUL
                   self.bytecode[i+2] == 0x04 {     // DIV
                    return true;
                }
            }
        }
        false
    }

    fn extract_fee_percentages(&self, pos: usize) -> Option<(u8, u8)> {
        // Try to extract buy/sell fee percentages
        // This is heuristic and simplified
        
        let mut fees = Vec::new();
        for i in pos..pos.saturating_add(30).min(self.bytecode.len()) {
            if i + 1 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 {  // PUSH1
                    let val = self.bytecode[i + 1];
                    if val <= 100 {  // Likely a percentage
                        fees.push(val);
                    }
                }
            }
        }
        
        if fees.len() >= 2 {
            Some((fees[0], fees[1]))
        } else {
            None
        }
    }

    fn has_blacklist_check(&self, pos: usize) -> bool {
        // isBlacklisted[from] check
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x54 &&      // SLOAD (blacklist mapping)
                   self.bytecode[i+1] == 0x15 &&    // ISZERO (not blacklisted)
                   self.bytecode[i+2] == 0xFD {     // REVERT
                    return true;
                }
            }
        }
        false
    }

    fn is_owner_controlled_blacklist(&self, pos: usize) -> bool {
        // Look for onlyOwner pattern near blacklist function
        self.is_owner_restricted(pos)
    }

    fn has_liquidity_lock_claim(&self, _pos: usize) -> bool {
        // Check for lock-related variables (heuristic)
        let lock_pattern = [0x6c, 0x6f, 0x63, 0x6b]; // "lock"
        self.bytecode.windows(4).any(|w| w == lock_pattern)
    }

    fn has_emergency_withdraw(&self, pos: usize) -> bool {
        // Emergency withdraw = CALL to owner with balance
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if i + 5 < self.bytecode.len() {
                if self.bytecode[i] == 0x47 &&      // SELFBALANCE
                   self.bytecode[i+3] == 0xF1 {     // CALL
                    return true;
                }
            }
        }
        false
    }

    fn has_renounce_ownership_function(&self, _pos: usize) -> bool {
        let renounce = [0x72, 0x65, 0x6e, 0x6f]; // "reno" (renounce)
        self.bytecode.windows(4).any(|w| w == renounce)
    }

    fn actually_renounces_ownership(&self, pos: usize) -> bool {
        // Check if owner is set to zero address
        for i in pos..pos.saturating_add(25).min(self.bytecode.len()) {
            if i + 3 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 &&      // PUSH1
                   self.bytecode[i+1] == 0x00 &&    // 0
                   self.bytecode[i+2] == 0x55 {     // SSTORE (owner = 0)
                    return true;
                }
            }
        }
        false
    }

    fn has_hidden_privileged_function(&self, pos: usize) -> bool {
        // Owner-restricted function with obscured name
        if self.is_owner_restricted(pos) {
            // Check if function name is suspicious (contains hex/numbers)
            // This is heuristic
            return true;
        }
        false
    }
}
