/// PREVRANDAO Weak Randomness Vulnerability Detector
///
/// Detects misuse of PREVRANDAO (formerly DIFFICULTY) for randomness after the Merge.
/// Post-merge, DIFFICULTY opcode returns PREVRANDAO (beacon chain randomness).
///
/// Why dangerous:
/// - PREVRANDAO is NOT unpredictable for validators
/// - Validators can manipulate by choosing to propose or not
/// - Small economic cost to manipulate (~0.1 ETH opportunity cost)
/// - Predictable for next block proposer
///
/// PREVRANDAO properties:
/// - Updated every block with beacon chain randomness
/// - Validators know value 1 block ahead
/// - Can be manipulated by skipping block proposal
/// - Better than block.timestamp but still exploitable
///
/// Real risks:
/// - NFT mints manipulated (rare traits)
/// - Lottery outcomes predicted
/// - Validator MEV extraction
/// - $5M+ in manipulated randomness
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableNFT {
///     uint256 public nextTokenId;
///     
///     function mint() external payable {
///         require(msg.value == 0.1 ether);
///         
///         // ❌ WRONG: Validator can manipulate!
///         uint256 randomness = block.prevrandao;
///         uint256 rarity = randomness % 100;
///         
///         if (rarity < 5) {
///             // Legendary (5% chance)
///             _mintLegendary(msg.sender);
///         } else {
///             _mintCommon(msg.sender);
///         }
///     }
/// }
///
/// // Validator attack:
/// // - Check prevrandao for next block
/// // - If gives legendary: propose block + mint
/// // - If gives common: skip block (lose ~0.1 ETH)
/// // - Expected value: legendary worth > 0.1 ETH → profitable!
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrevrandaoVulnerability {
    pub vulnerability_type: PrevrandaoIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrevrandaoIssueType {
    PrevrandaoForRandomness,       // PREVRANDAO/DIFFICULTY used for randomness
    PrevrandaoInHighValue,         // Used for high-value decisions
    PrevrandaoWithoutCommit,       // No commit-reveal scheme
    PrevrandaoInLottery,           // Used in lottery/raffle
    PrevrandaoForNFTRarity,        // Used for NFT trait assignment
}

pub struct PrevrandaoWeakRandomnessDetector {
    bytecode: Vec<u8>,
}

impl PrevrandaoWeakRandomnessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PrevrandaoVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_prevrandao_usage());
        vulnerabilities.extend(self.detect_difficulty_usage());

        vulnerabilities
    }

    fn detect_prevrandao_usage(&self) -> Vec<PrevrandaoVulnerability> {
        let mut vulnerabilities = Vec::new();

        // PREVRANDAO opcode is 0x44 (same as old DIFFICULTY)
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x44 { // PREVRANDAO/DIFFICULTY
                // Check if used in modulo operation (randomness)
                if self.has_modulo_after(i) {
                    vulnerabilities.push(PrevrandaoVulnerability {
                        vulnerability_type: PrevrandaoIssueType::PrevrandaoForRandomness,
                        severity: SecuritySeverity::High,
                        confidence: 0.85,
                        description: "PREVRANDAO used for randomness - validator manipulation risk".to_string(),
                        exploit_scenario: format!(
                            "PREVRANDAO RANDOMNESS at position {}:\n\
                            \n\
                            CRITICAL: PREVRANDAO used for random number generation!\n\
                            Post-merge, validators can manipulate this value.\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract VulnerableLottery {{\n\
                                address[] public participants;\n\
                                uint256 public prizePool;\n\
                                \n\
                                function drawWinner() external {{\n\
                                    require(participants.length > 0);\n\
                                    \n\
                                    // ❌ EXPLOITABLE!\n\
                                    uint256 randomIndex = block.prevrandao % participants.length;\n\
                                    address winner = participants[randomIndex];\n\
                                    \n\
                                    payable(winner).transfer(prizePool);\n\
                                    prizePool = 0;\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            VALIDATOR MANIPULATION:\n\
                            ```\n\
                            Validator is selected to propose block N:\n\
                            \n\
                            1. Validator checks PREVRANDAO for block N (known ahead)\n\
                            2. Calculate: winner = prevrandao % participants.length\n\
                            3. If winner == validator's address:\n\
                                → Propose block + call drawWinner()\n\
                                → Win prize!\n\
                            4. If winner != validator:\n\
                                → Skip block proposal\n\
                                → Lose ~0.1 ETH block reward\n\
                                → But avoid losing lottery\n\
                            \n\
                            Expected Value:\n\
                            - Prize pool: 10 ETH\n\
                            - Participants: 100\n\
                            - Chance of winning: 1%\n\
                            - Cost to manipulate: 0.1 ETH (skipped block)\n\
                            - EV of manipulation: 10 ETH * 0.01 = 0.1 ETH\n\
                            - If can manipulate multiple times → PROFITABLE!\n\
                            ```\n\
                            \n\
                            NFT RARITY MANIPULATION:\n\
                            ```solidity\n\
                            contract VulnerableNFT {{\n\
                                function mint() external payable {{\n\
                                    require(msg.value == 0.1 ether);\n\
                                    \n\
                                    // ❌ Rarity based on prevrandao\n\
                                    uint256 rarity = block.prevrandao % 1000;\n\
                                    \n\
                                    if (rarity < 10) {{\n\
                                        // Ultra rare 1% - worth 100 ETH\n\
                                        _mintUltraRare();\n\
                                    }} else if (rarity < 100) {{\n\
                                        // Rare 10% - worth 5 ETH\n\
                                        _mintRare();\n\
                                    }} else {{\n\
                                        // Common 89% - worth 0.2 ETH\n\
                                        _mintCommon();\n\
                                    }}\n\
                                }}\n\
                            }}\n\
                            \n\
                            // Validator attack:\n\
                            // Check if next prevrandao gives ultra rare\n\
                            // If yes: propose block + mint (gain 100 ETH - 0.1 ETH = 99.9 ETH)\n\
                            // If no: skip block (lose 0.1 ETH block reward)\n\
                            // With multiple opportunities → guaranteed profit!\n\
                            ```\n\
                            \n\
                            HISTORICAL CONTEXT:\n\
                            \n\
                            Pre-merge (PoW):\n\
                            - block.difficulty = mining difficulty\n\
                            - Still weak but harder to manipulate\n\
                            - Required hash power manipulation\n\
                            \n\
                            Post-merge (PoS):\n\
                            - block.difficulty → block.prevrandao\n\
                            - MUCH easier to manipulate\n\
                            - Validator just skips block\n\
                            - Cost: ~0.1 ETH opportunity cost\n\
                            \n\
                            SAFE ALTERNATIVES:\n\
                            \n\
                            1. Chainlink VRF (Best):\n\
                            ```solidity\n\
                            import '@chainlink/contracts/src/v0.8/VRFConsumerBase.sol';\n\
                            \n\
                            contract SafeLottery is VRFConsumerBase {{\n\
                                bytes32 internal keyHash;\n\
                                uint256 internal fee;\n\
                                \n\
                                function drawWinner() external {{\n\
                                    // Request truly random number\n\
                                    requestRandomness(keyHash, fee);\n\
                                }}\n\
                                \n\
                                function fulfillRandomness(bytes32 requestId, uint256 randomness) \n\
                                    internal override \n\
                                {{\n\
                                    // ✓ Unpredictable, unforgeable randomness\n\
                                    uint256 winnerIndex = randomness % participants.length;\n\
                                    payable(participants[winnerIndex]).transfer(prizePool);\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            2. Commit-Reveal Scheme:\n\
                            ```solidity\n\
                            contract CommitRevealLottery {{\n\
                                mapping(address => bytes32) public commits;\n\
                                uint256 public commitDeadline;\n\
                                uint256 public revealDeadline;\n\
                                \n\
                                // Phase 1: Commit\n\
                                function commit(bytes32 hash) external {{\n\
                                    require(block.timestamp < commitDeadline);\n\
                                    commits[msg.sender] = hash;\n\
                                }}\n\
                                \n\
                                // Phase 2: Reveal\n\
                                function reveal(uint256 secret) external {{\n\
                                    require(block.timestamp >= commitDeadline);\n\
                                    require(block.timestamp < revealDeadline);\n\
                                    require(keccak256(abi.encode(secret)) == commits[msg.sender]);\n\
                                    \n\
                                    // Combine all revealed secrets\n\
                                    randomSeed ^= uint256(keccak256(abi.encode(secret)));\n\
                                }}\n\
                                \n\
                                // Phase 3: Draw\n\
                                function draw() external {{\n\
                                    require(block.timestamp >= revealDeadline);\n\
                                    uint256 winner = randomSeed % participants.length;\n\
                                    // ...\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            3. Future Block Hash (Partial):\n\
                            ```solidity\n\
                            // Better than prevrandao but still has issues\n\
                            uint256 public drawBlock;\n\
                            \n\
                            function startDraw() external {{\n\
                                drawBlock = block.number + 10; // 10 blocks in future\n\
                            }}\n\
                            \n\
                            function completeDraw() external {{\n\
                                require(block.number > drawBlock);\n\
                                // Use blockhash of past block\n\
                                uint256 randomness = uint256(blockhash(drawBlock));\n\
                                // Still manipulable but more expensive\n\
                            }}\n\
                            ```\n\
                            \n\
                            SEVERITY: HIGH\n\
                            - Easy to exploit for validators\n\
                            - Low cost to manipulate (~0.1 ETH)\n\
                            - High impact on high-value decisions\n\
                            - Use Chainlink VRF or commit-reveal instead",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_difficulty_usage(&self) -> Vec<PrevrandaoVulnerability> {
        let mut vulnerabilities = Vec::new();

        // DIFFICULTY is same opcode as PREVRANDAO (0x44)
        // Already covered by detect_prevrandao_usage
        // This is just for clarity/documentation

        vulnerabilities
    }

    fn has_modulo_after(&self, pos: usize) -> bool {
        // Look for MOD operation after PREVRANDAO (indicates randomness usage)
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x06 { // MOD
                return true;
            }
        }
        false
    }
}
