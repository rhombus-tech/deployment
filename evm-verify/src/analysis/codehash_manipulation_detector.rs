/// CODEHASH Manipulation Vulnerability Detector
///
/// Detects dangerous uses of EXTCODEHASH opcode and code verification bypass patterns.
/// EXTCODEHASH returns keccak256(code) of an address, or 0 if account doesn't exist.
///
/// Critical patterns:
/// - EXTCODEHASH used for "is contract" checks (fails during construction!)
/// - CREATE2 address prediction without proper validation
/// - Metamorphic contracts (code changes at same address)
/// - Code verification bypass via constructor phase
///
/// Why dangerous:
/// - During construction, EXTCODEHASH returns 0 (no code yet!)
/// - Attacker can bypass "must be EOA" checks
/// - CREATE2 allows same address deployment after SELFDESTRUCT
/// - Metamorphic contracts can change behavior
///
/// Real exploits:
/// - Tornado Cash governance: $580k stolen via metamorphic contract
/// - Multiple CREATE2 + SELFDESTRUCT exploits: $2M+ cumulative
/// - "Is contract" bypass causing authorization failures
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableWhitelist {
///     mapping(address => bool) public whitelisted;
///     
///     function addToWhitelist(address user) external {
///         // ❌ WRONG: This can be bypassed!
///         require(extcodehash(user) == bytes32(0), "Only EOA");
///         
///         whitelisted[user] = true;
///     }
///     
///     function claimReward() external {
///         require(whitelisted[msg.sender], "Not whitelisted");
///         // Send reward
///     }
/// }
///
/// // Attack:
/// contract Attacker {
///     constructor(VulnerableWhitelist target) {
///         // During construction, extcodehash(this) == 0!
///         // So this passes the "Only EOA" check
///         target.addToWhitelist(address(this));
///     }
///     
///     function exploit(VulnerableWhitelist target) external {
///         target.claimReward(); // Now we're whitelisted!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodehashVulnerability {
    pub vulnerability_type: CodehashIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodehashIssueType {
    ExtcodehashIsContractCheck,    // Using EXTCODEHASH to check if account is contract
    ExtcodehashZeroCheck,          // Checking if EXTCODEHASH == 0 for "is EOA"
    Create2WithoutValidation,      // CREATE2 without proper code validation
    MetamorphicContractRisk,       // Pattern allowing metamorphic contracts
    CodeVerificationBypass,        // Code verification that can be bypassed
}

pub struct CodehashManipulationDetector {
    bytecode: Vec<u8>,
}

impl CodehashManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CodehashVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_extcodehash_eoa_check());
        vulnerabilities.extend(self.detect_extcodehash_zero_comparison());
        vulnerabilities.extend(self.detect_create2_metamorphic_risk());

        vulnerabilities
    }

    // ============ EXTCODEHASH EOA CHECK ============
    
    fn detect_extcodehash_eoa_check(&self) -> Vec<CodehashVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: EXTCODEHASH → comparison → JUMPI/REVERT
        // This is trying to check if address is contract/EOA
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x3F { // EXTCODEHASH opcode
                // Check if result is compared (likely for validation)
                if self.has_comparison_after(i) {
                    vulnerabilities.push(CodehashVulnerability {
                        vulnerability_type: CodehashIssueType::ExtcodehashIsContractCheck,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "EXTCODEHASH used for contract detection - constructor bypass risk".to_string(),
                        exploit_scenario: format!(
                            "EXTCODEHASH CONTRACT CHECK at position {}:\n\
                            \n\
                            CRITICAL VULNERABILITY:\n\
                            EXTCODEHASH returns 0 during contract construction!\n\
                            Attacker can bypass \"must be EOA\" checks.\n\
                            \n\
                            VULNERABLE CODE:\n\
                            ```solidity\n\
                            contract VulnerableAirdrop {{\n\
                                mapping(address => bool) public claimed;\n\
                                \n\
                                function claim() external {{\n\
                                    // ❌ WRONG: Trying to prevent contracts from claiming\n\
                                    require(extcodehash(msg.sender) == bytes32(0), 'No contracts!');\n\
                                    \n\
                                    require(!claimed[msg.sender], 'Already claimed');\n\
                                    claimed[msg.sender] = true;\n\
                                    \n\
                                    // Send airdrop tokens\n\
                                    token.transfer(msg.sender, AIRDROP_AMOUNT);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            ATTACK CONTRACT:\n\
                            ```solidity\n\
                            contract AirdropExploiter {{\n\
                                VulnerableAirdrop public airdrop;\n\
                                \n\
                                constructor(VulnerableAirdrop _airdrop) {{\n\
                                    airdrop = _airdrop;\n\
                                    \n\
                                    // CRITICAL: During construction, extcodehash(this) == bytes32(0)\n\
                                    // So the 'No contracts!' check passes!\n\
                                    airdrop.claim();\n\
                                    \n\
                                    // Tokens received, transfer to EOA\n\
                                    IERC20 token = IERC20(airdrop.token());\n\
                                    token.transfer(msg.sender, token.balanceOf(address(this)));\n\
                                }}\n\
                            }}\n\
                            \n\
                            // To exploit:\n\
                            // Deploy many AirdropExploiter contracts in a loop\n\
                            // Each one claims airdrop during construction\n\
                            // All tokens drained\n\
                            ```\n\
                            \n\
                            WHY EXTCODEHASH FAILS:\n\
                            \n\
                            During contract construction:\n\
                            1. Constructor code is executing\n\
                            2. But contract code is NOT yet stored at address\n\
                            3. EXTCODEHASH(address) returns 0 (no code exists yet)\n\
                            4. After constructor completes, code is stored\n\
                            5. Then EXTCODEHASH returns actual codehash\n\
                            \n\
                            Timeline:\n\
                            ```\n\
                            Block N:     Create contract\n\
                            ├─ Start:    extcodehash(addr) = 0x00...00 ❌\n\
                            ├─ Constructor runs\n\
                            │  └─ claim() called\n\
                            │     └─ extcodehash(msg.sender) == 0 ✓ passes!\n\
                            ├─ Constructor ends\n\
                            └─ End:      extcodehash(addr) = 0xabcd...ef ✓\n\
                            ```\n\
                            \n\
                            REAL WORLD EXAMPLE: NFT Whitelist\n\
                            ```solidity\n\
                            contract VulnerableNFT {{\n\
                                mapping(address => bool) public whitelisted;\n\
                                uint256 public constant MAX_PER_ADDRESS = 1;\n\
                                mapping(address => uint256) public minted;\n\
                                \n\
                                function addToWhitelist(address user) external onlyOwner {{\n\
                                    // ❌ Owner thinks this prevents contracts\n\
                                    require(extcodehash(user) == bytes32(0), 'EOA only');\n\
                                    whitelisted[user] = true;\n\
                                }}\n\
                                \n\
                                function mint() external {{\n\
                                    require(whitelisted[msg.sender], 'Not whitelisted');\n\
                                    require(minted[msg.sender] < MAX_PER_ADDRESS, 'Already minted');\n\
                                    \n\
                                    minted[msg.sender]++;\n\
                                    _mint(msg.sender, nextTokenId++);\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Attack:\n\
                            contract NFTExploiter {{\n\
                                constructor(VulnerableNFT nft) {{\n\
                                    // Get whitelisted during construction\n\
                                    nft.owner().call(\n\
                                        abi.encodeWithSignature('addToWhitelist(address)', address(this))\n\
                                    );\n\
                                }}\n\
                                \n\
                                function exploit(VulnerableNFT nft) external {{\n\
                                    // Now mint (we're whitelisted)\n\
                                    nft.mint();\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Deploy 1000 NFTExploiter contracts\n\
                            // Each gets whitelisted during construction\n\
                            // Then each mints NFT\n\
                            // Result: 1000 NFTs to attacker (should be 1 per EOA)\n\
                            ```\n\
                            \n\
                            CORRECT IMPLEMENTATIONS:\n\
                            \n\
                            Option 1: Use tx.origin == msg.sender\n\
                            ```solidity\n\
                            function claim() external {{\n\
                                // ✓ This ensures direct EOA call\n\
                                require(tx.origin == msg.sender, 'EOA only');\n\
                                // Warning: This prevents ALL contract calls (including multisigs)\n\
                                claimed[msg.sender] = true;\n\
                                token.transfer(msg.sender, AIRDROP_AMOUNT);\n\
                            }}\n\
                            ```\n\
                            \n\
                            Option 2: Combine extcodesize AND extcodehash\n\
                            ```solidity\n\
                            function claim() external {{\n\
                                uint256 size;\n\
                                assembly {{ size := extcodesize(caller()) }}\n\
                                \n\
                                // ✓ extcodesize is also 0 during construction\n\
                                // BUT we can check later too\n\
                                require(size == 0, 'No contracts');\n\
                                require(extcodehash(msg.sender) == bytes32(0), 'No contracts');\n\
                                \n\
                                claimed[msg.sender] = true;\n\
                                token.transfer(msg.sender, AIRDROP_AMOUNT);\n\
                            }}\n\
                            ```\n\
                            \n\
                            Option 3: Two-step process (BEST)\n\
                            ```solidity\n\
                            mapping(address => uint256) public claimableFrom;\n\
                            \n\
                            function register() external {{\n\
                                require(tx.origin == msg.sender, 'EOA only');\n\
                                // Claimable after 1 block delay\n\
                                claimableFrom[msg.sender] = block.number + 1;\n\
                            }}\n\
                            \n\
                            function claim() external {{\n\
                                require(block.number >= claimableFrom[msg.sender], 'Not registered');\n\
                                \n\
                                // Now we can safely check\n\
                                uint256 size;\n\
                                assembly {{ size := extcodesize(caller()) }}\n\
                                require(size == 0, 'No contracts');\n\
                                \n\
                                claimableFrom[msg.sender] = 0;\n\
                                token.transfer(msg.sender, AIRDROP_AMOUNT);\n\
                            }}\n\
                            ```\n\
                            \n\
                            IMPACT:\n\
                            - Airdrop/whitelist bypass: Multiple protocols affected\n\
                            - NFT mint limits circumvented\n\
                            - Governance voting manipulation\n\
                            - Rate limiting bypass\n\
                            \n\
                            FIX PRIORITY: HIGH\n\
                            - Easy to exploit (simple constructor call)\n\
                            - Affects many contracts trying to prevent bot usage\n\
                            - Can drain entire airdrop/mint supply",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ EXTCODEHASH ZERO COMPARISON ============
    
    fn detect_extcodehash_zero_comparison(&self) -> Vec<CodehashVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: EXTCODEHASH → PUSH 0 → EQ
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x3F { // EXTCODEHASH
                if self.has_zero_comparison_after(i) {
                    vulnerabilities.push(CodehashVulnerability {
                        vulnerability_type: CodehashIssueType::ExtcodehashZeroCheck,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "Checking if extcodehash == 0 - unreliable for EOA detection".to_string(),
                        exploit_scenario: format!(
                            "EXTCODEHASH ZERO CHECK at position {}:\n\
                            \n\
                            Code checks if extcodehash(address) == 0.\n\
                            This is UNRELIABLE for detecting EOAs because:\n\
                            \n\
                            1. Returns 0 during contract construction (bypass)\n\
                            2. Returns 0 for non-existent accounts (may not be EOA)\n\
                            3. After selfdestruct, returns 0 (but was contract)\n\
                            \n\
                            Use tx.origin == msg.sender for EOA checks instead.",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ CREATE2 METAMORPHIC RISK ============
    
    fn detect_create2_metamorphic_risk(&self) -> Vec<CodehashVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CREATE2 opcode present
        // Metamorphic contracts: deploy → selfdestruct → redeploy same address with different code
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xF5 { // CREATE2
                vulnerabilities.push(CodehashVulnerability {
                    vulnerability_type: CodehashIssueType::Create2WithoutValidation,
                    severity: SecuritySeverity::Medium,
                    confidence: 0.75,
                    description: "CREATE2 usage - beware of metamorphic contract risk".to_string(),
                    exploit_scenario: format!(
                        "CREATE2 DETECTED at position {}:\n\
                        \n\
                        CREATE2 allows deploying contracts to deterministic addresses.\n\
                        Combined with SELFDESTRUCT, this enables metamorphic contracts:\n\
                        \n\
                        METAMORPHIC CONTRACT ATTACK:\n\
                        ```solidity\n\
                        // Step 1: Deploy benign contract at address A\n\
                        create2(salt, benignBytecode) → address A\n\
                        \n\
                        // Step 2: Get contract verified/whitelisted\n\
                        // Address A now trusted by protocols\n\
                        \n\
                        // Step 3: Self-destruct contract\n\
                        selfdestruct(attacker)\n\
                        \n\
                        // Step 4: Deploy malicious contract to SAME address A\n\
                        create2(salt, maliciousBytecode) → address A\n\
                        \n\
                        // Now address A has different code but same address!\n\
                        ```\n\
                        \n\
                        REAL EXPLOIT: Tornado Cash Governance ($580k)\n\
                        Attacker used metamorphic contract to bypass proposal validation.\n\
                        \n\
                        DEFENSE:\n\
                        - Verify code hash, not just address\n\
                        - Re-validate contracts after critical operations\n\
                        - Use immutable contracts (no selfdestruct)",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn has_comparison_after(&self, pos: usize) -> bool {
        // Look for comparison operations after EXTCODEHASH
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 || // EQ
               self.bytecode[i] == 0x10 || // LT
               self.bytecode[i] == 0x11 {  // GT
                return true;
            }
        }
        false
    }

    fn has_zero_comparison_after(&self, pos: usize) -> bool {
        // Pattern: PUSH 0 → EQ after EXTCODEHASH
        for i in pos..pos.saturating_add(10).min(self.bytecode.len()) {
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == 0x60 && // PUSH1
                   self.bytecode[i+1] == 0x00 && // 0
                   self.bytecode[i+2] == 0x14 { // EQ
                    return true;
                }
            }
        }
        false
    }
}
