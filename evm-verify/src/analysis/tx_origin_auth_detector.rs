/// TX.ORIGIN Authentication Vulnerability Detector
///
/// Detects dangerous use of tx.origin for authentication and access control.
/// tx.origin returns the original sender of the transaction, not the immediate caller.
///
/// Why dangerous:
/// - tx.origin can be manipulated via phishing contracts
/// - User calls malicious contract → malicious contract calls victim → tx.origin = user
/// - Attacker can bypass authentication if victim uses tx.origin
/// - msg.sender is ALWAYS safer than tx.origin
///
/// Critical patterns:
/// - tx.origin used in require/if for access control
/// - tx.origin compared to owner/admin address
/// - tx.origin used for authorization without msg.sender check
/// - onlyOwner modifier using tx.origin instead of msg.sender
///
/// Real exploits:
/// - Wallet drainers: User approves malicious contract, contract drains wallet
/// - THORChain router exploit pattern (not direct but similar)
/// - Numerous phishing attacks using tx.origin confusion
/// - $5M+ in cumulative losses from tx.origin phishing
///
/// Example vulnerability:
/// ```solidity
/// contract Vulnerable {
///     address public owner;
///     
///     constructor() {
///         owner = msg.sender;
///     }
///     
///     // ❌ VULNERABLE - uses tx.origin!
///     modifier onlyOwner() {
///         require(tx.origin == owner, "Not owner");
///         _;
///     }
///     
///     function withdraw() external onlyOwner {
///         payable(owner).transfer(address(this).balance);
///     }
/// }
///
/// // Attack:
/// contract Attacker {
///     function attack(Vulnerable victim) external {
///         // When victim's owner calls this:
///         // tx.origin = owner
///         // msg.sender = Attacker
///         // tx.origin check passes!
///         victim.withdraw();
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOriginAuthVulnerability {
    pub vulnerability_type: TxOriginIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxOriginIssueType {
    TxOriginInAccessControl,      // tx.origin used for access control
    TxOriginInOwnerCheck,          // tx.origin compared to owner address
    TxOriginInRequire,             // tx.origin in require statement
    TxOriginInConditional,         // tx.origin in if/else logic
    TxOriginWithoutMsgSender,      // tx.origin used but msg.sender not checked
}

pub struct TxOriginAuthDetector {
    bytecode: Vec<u8>,
}

impl TxOriginAuthDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TxOriginAuthVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_tx_origin_in_access_control());
        vulnerabilities.extend(self.detect_tx_origin_in_owner_check());
        vulnerabilities.extend(self.detect_tx_origin_without_msg_sender());

        vulnerabilities
    }

    // ============ TX.ORIGIN IN ACCESS CONTROL ============
    
    fn detect_tx_origin_in_access_control(&self) -> Vec<TxOriginAuthVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: ORIGIN followed by EQ and JUMPI/REVERT
        // This is the classic onlyOwner using tx.origin
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x32 { // ORIGIN opcode
                // Check if followed by comparison and conditional jump
                if self.has_access_control_pattern_after(i) {
                    vulnerabilities.push(TxOriginAuthVulnerability {
                        vulnerability_type: TxOriginIssueType::TxOriginInAccessControl,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.90,
                        description: "tx.origin used for access control - CRITICAL PHISHING RISK".to_string(),
                        exploit_scenario: format!(
                            "TX.ORIGIN AUTHENTICATION BYPASS at position {}:\n\
                            \n\
                            VULNERABLE CODE:\n\
                            ```solidity\n\
                            contract VulnerableWallet {{\n\
                                address public owner;\n\
                                \n\
                                constructor() {{\n\
                                    owner = msg.sender;\n\
                                }}\n\
                                \n\
                                // ❌ CRITICAL VULNERABILITY\n\
                                modifier onlyOwner() {{\n\
                                    require(tx.origin == owner, 'Not owner');\n\
                                    // This checks the TRANSACTION ORIGIN, not the caller!\n\
                                    _;\n\
                                }}\n\
                                \n\
                                function withdraw() external onlyOwner {{\n\
                                    payable(owner).transfer(address(this).balance);\n\
                                }}\n\
                                \n\
                                function execute(address target, bytes calldata data) \n\
                                    external onlyOwner \n\
                                {{\n\
                                    target.call(data);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK CONTRACT:\n\
                            ```solidity\n\
                            contract PhishingAttack {{\n\
                                VulnerableWallet public victim;\n\
                                \n\
                                constructor(VulnerableWallet _victim) {{\n\
                                    victim = _victim;\n\
                                }}\n\
                                \n\
                                // Looks innocent - 'claim airdrop'\n\
                                function claimAirdrop() external {{\n\
                                    // When victim calls this:\n\
                                    // tx.origin = victim (the owner)\n\
                                    // msg.sender = PhishingAttack\n\
                                    \n\
                                    // This PASSES the onlyOwner check!\n\
                                    // Because tx.origin == owner\n\
                                    victim.withdraw();\n\
                                    \n\
                                    // Attacker receives all funds\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK FLOW:\n\
                            1. Attacker deploys PhishingAttack contract\n\
                            2. Attacker tricks victim: 'Call claimAirdrop() to get free tokens!'\n\
                            3. Victim calls PhishingAttack.claimAirdrop()\n\
                            4. tx.origin = victim (the wallet owner)\n\
                            5. PhishingAttack calls victim.withdraw()\n\
                            6. onlyOwner check: tx.origin == owner ✓ PASSES\n\
                            7. All funds withdrawn to attacker\n\
                            \n\
                            REAL WORLD EXAMPLES:\n\
                            \n\
                            Example 1: Wallet Drainer\n\
                            ```solidity\n\
                            contract DrainerAttack {{\n\
                                function drain(VulnerableWallet wallet, address token) external {{\n\
                                    // When victim calls this:\n\
                                    bytes memory data = abi.encodeWithSignature(\n\
                                        'transfer(address,uint256)',\n\
                                        attacker,\n\
                                        IERC20(token).balanceOf(address(wallet))\n\
                                    );\n\
                                    \n\
                                    // tx.origin = victim, so execute() passes!\n\
                                    wallet.execute(token, data);\n\
                                    // All tokens drained\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            Example 2: Multi-Sig Bypass\n\
                            ```solidity\n\
                            contract VulnerableMultiSig {{\n\
                                mapping(address => bool) public signers;\n\
                                \n\
                                function executeTransaction(address target, bytes calldata data) \n\
                                    external \n\
                                {{\n\
                                    require(signers[tx.origin], 'Not signer'); // ❌\n\
                                    target.call(data);\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Attacker tricks any signer to call malicious contract\n\
                            // Malicious contract calls executeTransaction\n\
                            // tx.origin = signer → check passes → multisig bypassed!\n\
                            ```\n\
                            \n\
                            WHY THIS IS CRITICAL:\n\
                            \n\
                            1. **Phishing is Easy**: Users constantly interact with contracts\n\
                            2. **No Warning**: Wallet shows normal transaction\n\
                            3. **Invisible Attack**: Victim thinks they're claiming airdrop\n\
                            4. **Total Loss**: Attacker gets complete access\n\
                            5. **Irreversible**: No way to recover funds\n\
                            \n\
                            CORRECT IMPLEMENTATION:\n\
                            ```solidity\n\
                            modifier onlyOwner() {{\n\
                                require(msg.sender == owner, 'Not owner');\n\
                                // ✓ Use msg.sender, not tx.origin!\n\
                                _;\n\
                            }}\n\
                            \n\
                            // If you REALLY need tx.origin (rare), combine with msg.sender:\n\
                            modifier onlyOwnerDirect() {{\n\
                                require(msg.sender == owner, 'Not owner');\n\
                                require(tx.origin == msg.sender, 'No contract calls');\n\
                                // This ensures owner called directly, not via another contract\n\
                                _;\n\
                            }}\n\
                            ```\n\
                            \n\
                            SAFE PATTERN:\n\
                            - ALWAYS use msg.sender for access control\n\
                            - NEVER use tx.origin alone for authorization\n\
                            - If blocking contracts, use: tx.origin == msg.sender\n\
                            - Add explicit documentation if tx.origin is intentional\n\
                            \n\
                            HISTORICAL LOSSES:\n\
                            - Multiple wallet drainers: $5M+ cumulative\n\
                            - DeFi protocol exploits using tx.origin\n\
                            - NFT marketplace vulnerabilities\n\
                            - Gaming platforms with tx.origin auth\n\
                            \n\
                            SEVERITY: CRITICAL\n\
                            - Easy to exploit via phishing\n\
                            - No special skills required\n\
                            - Total loss of funds\n\
                            - Affects all users who interact with malicious contracts",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ TX.ORIGIN IN OWNER CHECK ============
    
    fn detect_tx_origin_in_owner_check(&self) -> Vec<TxOriginAuthVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: ORIGIN → SLOAD (loading owner) → EQ
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x32 { // ORIGIN
                // Check if followed by storage load (owner address) and comparison
                if self.has_owner_comparison_pattern_after(i) {
                    vulnerabilities.push(TxOriginAuthVulnerability {
                        vulnerability_type: TxOriginIssueType::TxOriginInOwnerCheck,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: "tx.origin compared to owner address for authorization".to_string(),
                        exploit_scenario: format!(
                            "TX.ORIGIN OWNER CHECK at position {}:\n\
                            \n\
                            Pattern detected: tx.origin == owner\n\
                            \n\
                            This allows any contract called by the owner to impersonate the owner.\n\
                            \n\
                            Attack: Owner interacts with malicious contract → malicious contract\n\
                            calls back to victim → tx.origin == owner → authorization bypassed.\n\
                            \n\
                            Fix: Replace with msg.sender == owner",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ TX.ORIGIN WITHOUT MSG.SENDER ============
    
    fn detect_tx_origin_without_msg_sender(&self) -> Vec<TxOriginAuthVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Find functions using ORIGIN but not CALLER (msg.sender)
        let origin_positions = self.find_all_origins();
        
        for &origin_pos in &origin_positions {
            // Check if msg.sender (CALLER opcode 0x33) is used nearby for additional check
            if !self.has_msg_sender_check_in_function(origin_pos) {
                vulnerabilities.push(TxOriginAuthVulnerability {
                    vulnerability_type: TxOriginIssueType::TxOriginWithoutMsgSender,
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: "tx.origin used without corresponding msg.sender check".to_string(),
                    exploit_scenario: format!(
                        "TX.ORIGIN WITHOUT MSG.SENDER at position {}:\n\
                        \n\
                        Function uses tx.origin but does not verify msg.sender.\n\
                        This is a red flag for authentication bypass vulnerabilities.\n\
                        \n\
                        Best practice: Always use msg.sender for access control.\n\
                        If tx.origin is needed, combine with msg.sender check.",
                        origin_pos
                    ),
                    location: origin_pos,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_access_control_pattern_after(&self, pos: usize) -> bool {
        // Look for: ORIGIN → ... → EQ → ISZERO/JUMPI/REVERT
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 { // EQ
                // Check for conditional jump or revert nearby
                for j in i..i.saturating_add(5).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 || // JUMPI
                       self.bytecode[j] == 0xFD {   // REVERT
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_owner_comparison_pattern_after(&self, pos: usize) -> bool {
        // ORIGIN → SLOAD → EQ pattern
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD (likely loading owner)
                for j in i..i.saturating_add(5).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ
                        return true;
                    }
                }
            }
        }
        false
    }

    fn find_all_origins(&self) -> Vec<usize> {
        self.bytecode.iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x32) // ORIGIN
            .map(|(i, _)| i)
            .collect()
    }

    fn has_msg_sender_check_in_function(&self, origin_pos: usize) -> bool {
        // Check if CALLER (msg.sender) appears in nearby code
        // Simple heuristic: check within 50 bytes before/after
        let start = origin_pos.saturating_sub(50);
        let end = (origin_pos + 50).min(self.bytecode.len());
        
        for i in start..end {
            if self.bytecode[i] == 0x33 { // CALLER (msg.sender)
                return true;
            }
        }
        false
    }
}
