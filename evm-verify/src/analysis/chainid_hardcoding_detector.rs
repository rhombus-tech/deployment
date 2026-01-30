/// ChainID Hardcoding Vulnerability Detector
///
/// Detects hardcoded CHAINID values that can cause signature replay on forks.
/// EIP-155 introduced CHAINID to prevent transaction replay across chains.
///
/// Why dangerous:
/// - Hardcoded chainID breaks on network forks
/// - Signature replay possible between original and forked chain
/// - Post-fork transactions can be replayed on both chains
/// - Affects permit signatures, meta-transactions, and EIP-712 signatures
///
/// Critical scenarios:
/// - Ethereum → Ethereum Classic fork
/// - Polygon → Polygon fork proposals
/// - Any contentious hardfork
///
/// Real risks:
/// - Post-fork asset double-spending
/// - Signature replay draining funds on both chains
/// - $10M+ at risk in fork scenarios
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerablePermit {
///     bytes32 public constant DOMAIN_SEPARATOR = keccak256(abi.encode(
///         keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
///         keccak256("MyToken"),
///         1,  // ❌ HARDCODED CHAINID!
///         address(this)
///     ));
///     
///     function permit(address owner, address spender, uint256 value, bytes calldata signature) external {
///         bytes32 digest = keccak256(abi.encodePacked(
///             "\x19\x01",
///             DOMAIN_SEPARATOR,
///             keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++))
///         ));
///         
///         address signer = ecrecover(digest, signature);
///         require(signer == owner, "Invalid signature");
///         _approve(owner, spender, value);
///     }
/// }
///
/// // If Ethereum forks to ETH and ETC:
/// // - Same contract deployed on both chains (same address via CREATE2)
/// // - User signs permit on ETH chain
/// // - Attacker replays signature on ETC chain
/// // - Both chains approve spending!
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIdVulnerability {
    pub vulnerability_type: ChainIdIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
    pub hardcoded_chainid: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainIdIssueType {
    HardcodedChainId,              // ChainID compared to constant
    ChainIdNotUsedInSignature,     // Signature verification without chainID
    ChainIdInConstructorOnly,      // ChainID cached in constructor (breaks on fork)
    MissingChainIdValidation,      // No chainID validation at all
}

pub struct ChainIdHardcodingDetector {
    bytecode: Vec<u8>,
}

impl ChainIdHardcodingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ChainIdVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_hardcoded_chainid());
        vulnerabilities.extend(self.detect_chainid_comparison());
        vulnerabilities.extend(self.detect_missing_chainid_in_sig());

        vulnerabilities
    }

    // ============ HARDCODED CHAINID ============
    
    fn detect_hardcoded_chainid(&self) -> Vec<ChainIdVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CHAINID opcode followed by comparison with constant
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x46 { // CHAINID opcode
                // Check if compared to a constant (common chainIDs: 1, 56, 137, 42161, etc.)
                if let Some(chainid) = self.get_compared_chainid_after(i) {
                    let severity = if chainid == 1 || chainid == 56 || chainid == 137 {
                        SecuritySeverity::High // Mainnet chains
                    } else {
                        SecuritySeverity::Medium
                    };

                    vulnerabilities.push(ChainIdVulnerability {
                        vulnerability_type: ChainIdIssueType::HardcodedChainId,
                        severity,
                        confidence: 0.90,
                        description: format!("ChainID hardcoded to {} - fork replay risk", chainid),
                        exploit_scenario: format!(
                            "HARDCODED CHAINID {} at position {}:\n\
                            \n\
                            CRITICAL: Signature Replay on Chain Forks\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract VulnerableEIP712 {{\n\
                                // ❌ ChainID hardcoded at deployment\n\
                                bytes32 public immutable DOMAIN_SEPARATOR = keccak256(\n\
                                    abi.encode(\n\
                                        EIP712_DOMAIN_TYPEHASH,\n\
                                        keccak256('MyProtocol'),\n\
                                        keccak256('1'),\n\
                                        {},  // HARDCODED!\n\
                                        address(this)\n\
                                    )\n\
                                );\n\
                                \n\
                                function executeMetaTx(\n\
                                    address user,\n\
                                    bytes calldata data,\n\
                                    bytes calldata signature\n\
                                ) external {{\n\
                                    bytes32 digest = keccak256(\n\
                                        abi.encodePacked('\\x19\\x01', DOMAIN_SEPARATOR, dataHash)\n\
                                    );\n\
                                    \n\
                                    require(ecrecover(digest, signature) == user, 'Invalid sig');\n\
                                    // Execute transaction\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            FORK SCENARIO:\n\
                            ```\n\
                            Block N:     Network operates normally\n\
                            Block N+1:   Contentious upgrade proposed\n\
                            Block N+2:   Community splits!\n\
                            \n\
                            Chain A (Original):  chainID = {}\n\
                            Chain B (Fork):      chainID = {} (stays same!)\n\
                            \n\
                            Both chains have same:\n\
                            - Contract addresses (deterministic deployment)\n\
                            - DOMAIN_SEPARATOR (hardcoded chainID)\n\
                            - User balances (at fork point)\n\
                            ```\n\
                            \n\
                            ATTACK:\n\
                            ```solidity\n\
                            // User on Chain A signs permit for 100 USDC\n\
                            signature_A = user.sign(permit(spender=DEX, amount=100));\n\
                            \n\
                            // User submits on Chain A → 100 USDC approved\n\
                            ChainA.executeMetaTx(user, permitData, signature_A);\n\
                            \n\
                            // Attacker monitors Chain A mempool\n\
                            // Sees signature, replays on Chain B!\n\
                            ChainB.executeMetaTx(user, permitData, signature_A);\n\
                            \n\
                            // REPLAY WORKS because:\n\
                            // - Same DOMAIN_SEPARATOR (hardcoded chainID)\n\
                            // - Same contract address\n\
                            // - Same signature validates!\n\
                            \n\
                            // User loses 100 USDC on BOTH chains!\n\
                            ```\n\
                            \n\
                            REAL WORLD FORK RISKS:\n\
                            \n\
                            Historical Forks:\n\
                            - Ethereum → Ethereum Classic (2016)\n\
                            - Bitcoin → Bitcoin Cash (2017)\n\
                            - Ethereum → Multiple consensus failures\n\
                            \n\
                            Future Fork Risks:\n\
                            - Any contentious protocol upgrade\n\
                            - Governance disputes\n\
                            - Security emergency forks\n\
                            - L2 sequencer failures\n\
                            \n\
                            IMPACT EXAMPLES:\n\
                            \n\
                            1. Token Approvals:\n\
                            ```solidity\n\
                            // User approves spending 1000 USDC on Chain A\n\
                            // Attacker replays → 1000 USDC approved on Chain B\n\
                            // Attacker drains both chains\n\
                            ```\n\
                            \n\
                            2. NFT Transfers:\n\
                            ```solidity\n\
                            // User lists NFT for sale on Chain A\n\
                            // Signs message to transfer ownership\n\
                            // Attacker replays on Chain B\n\
                            // NFT stolen on both chains\n\
                            ```\n\
                            \n\
                            3. Governance Votes:\n\
                            ```solidity\n\
                            // User votes YES on proposal (Chain A)\n\
                            // Attacker replays vote on Chain B\n\
                            // Same vote counted twice\n\
                            // Governance manipulation\n\
                            ```\n\
                            \n\
                            CORRECT IMPLEMENTATION:\n\
                            ```solidity\n\
                            contract SecureEIP712 {{\n\
                                bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(\n\
                                    'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'\n\
                                );\n\
                                \n\
                                // ✓ Compute DOMAIN_SEPARATOR dynamically\n\
                                function _domainSeparator() internal view returns (bytes32) {{\n\
                                    return keccak256(\n\
                                        abi.encode(\n\
                                            EIP712_DOMAIN_TYPEHASH,\n\
                                            keccak256('MyProtocol'),\n\
                                            keccak256('1'),\n\
                                            block.chainid,  // ✓ DYNAMIC!\n\
                                            address(this)\n\
                                        )\n\
                                    );\n\
                                }}\n\
                                \n\
                                // Alternative: Cache but recompute on fork\n\
                                bytes32 private _CACHED_DOMAIN_SEPARATOR;\n\
                                uint256 private _CACHED_CHAIN_ID;\n\
                                \n\
                                constructor() {{\n\
                                    _CACHED_CHAIN_ID = block.chainid;\n\
                                    _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator();\n\
                                }}\n\
                                \n\
                                function DOMAIN_SEPARATOR() public view returns (bytes32) {{\n\
                                    // ✓ Recompute if chainID changed (fork detected!)\n\
                                    if (block.chainid == _CACHED_CHAIN_ID) {{\n\
                                        return _CACHED_DOMAIN_SEPARATOR;\n\
                                    }} else {{\n\
                                        return _buildDomainSeparator();\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            OPENZEPPELIN PATTERN (BEST PRACTICE):\n\
                            ```solidity\n\
                            // From OpenZeppelin EIP712.sol\n\
                            function _domainSeparatorV4() internal view returns (bytes32) {{\n\
                                if (block.chainid == _CACHED_CHAIN_ID) {{\n\
                                    return _CACHED_DOMAIN_SEPARATOR;\n\
                                }} else {{\n\
                                    return _buildDomainSeparator();\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            FIX CHECKLIST:\n\
                            ✓ Never hardcode chainID in constants\n\
                            ✓ Use block.chainid for dynamic lookup\n\
                            ✓ Or cache but re-validate on each use\n\
                            ✓ Test with fork simulation\n\
                            ✓ Use OpenZeppelin's EIP712 implementation\n\
                            \n\
                            SEVERITY: HIGH on mainnets, MEDIUM on testnets",
                            chainid, i, chainid, chainid, chainid
                        ),
                        location: i,
                        hardcoded_chainid: Some(chainid),
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ CHAINID COMPARISON ============
    
    fn detect_chainid_comparison(&self) -> Vec<ChainIdVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CHAINID → comparison for conditional logic
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x46 { // CHAINID
                if self.has_conditional_logic_after(i) {
                    vulnerabilities.push(ChainIdVulnerability {
                        vulnerability_type: ChainIdIssueType::ChainIdInConstructorOnly,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "ChainID used in conditional logic - verify fork safety".to_string(),
                        exploit_scenario: format!(
                            "CHAINID CONDITIONAL at position {}:\n\
                            \n\
                            Contract behavior changes based on chainID.\n\
                            Ensure this logic handles forks correctly.\n\
                            \n\
                            If chainID is cached in constructor, it won't update on fork!",
                            i
                        ),
                        location: i,
                        hardcoded_chainid: None,
                    });
                }
            }
        }

        vulnerabilities
    }

    // ============ MISSING CHAINID IN SIGNATURES ============
    
    fn detect_missing_chainid_in_sig(&self) -> Vec<ChainIdVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for ecrecover usage without chainID validation
        let has_ecrecover = self.bytecode.iter().enumerate().any(|(i, &b)| {
            b == 0x01 && i > 0 && (self.bytecode[i-1] == 0xF1 || self.bytecode[i-1] == 0xFA)
        });

        let has_chainid = self.bytecode.iter().any(|&b| b == 0x46);

        if has_ecrecover && !has_chainid {
            vulnerabilities.push(ChainIdVulnerability {
                vulnerability_type: ChainIdIssueType::ChainIdNotUsedInSignature,
                severity: SecuritySeverity::High,
                confidence: 0.75,
                description: "Signature verification without chainID - replay risk".to_string(),
                exploit_scenario: "Contract uses ecrecover for signature verification but doesn't include chainID in signed data. Signatures can be replayed across different chains.".to_string(),
                location: 0,
                hardcoded_chainid: None,
            });
        }

        vulnerabilities
    }

    // ============ HELPER FUNCTIONS ============

    fn get_compared_chainid_after(&self, pos: usize) -> Option<u64> {
        // Look for PUSH followed by EQ after CHAINID
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                // PUSH operation
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if i + push_size < self.bytecode.len() {
                    // Check if followed by EQ
                    if i + push_size + 1 < self.bytecode.len() &&
                       self.bytecode[i + push_size + 1] == 0x14 {
                        // Extract the value
                        let mut value: u64 = 0;
                        for j in 0..push_size.min(8) {
                            value = (value << 8) | self.bytecode[i + 1 + j] as u64;
                        }
                        // Check if it looks like a chainID (common values)
                        if value == 1 || value == 56 || value == 137 || 
                           value == 42161 || value == 10 || value == 250 {
                            return Some(value);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_conditional_logic_after(&self, pos: usize) -> bool {
        // Look for JUMPI after chainID
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x57 { // JUMPI
                return true;
            }
        }
        false
    }
}
