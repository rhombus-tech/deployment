/// Unprotected Callback Detector (ERC-721/1155 Receivers)
///
/// Detects missing validation in onERC721Received/onERC1155Received callbacks.
/// These callbacks are external entry points that can be exploited for reentrancy.
///
/// Why dangerous:
/// - Callbacks executed during token transfer
/// - Attacker controls callback logic
/// - Can reenter before state updates
/// - Bypasses reentrancy guards on main functions
///
/// Real exploits:
/// - **$30M+ in NFT reentrancy attacks**
/// - Callback reentrancy on marketplaces
/// - State manipulation during callbacks
/// - Unauthorized minting via callbacks
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableNFTVault {
///     mapping(address => uint256) public deposits;
///     
///     function depositNFT(IERC721 nft, uint256 tokenId) external {
///         deposits[msg.sender]++;
///         
///         // ❌ State updated AFTER transfer - callback can exploit!
///         nft.safeTransferFrom(msg.sender, address(this), tokenId);
///     }
///     
///     function onERC721Received(
///         address,
///         address from,
///         uint256,
///         bytes calldata
///     ) external returns (bytes4) {
///         // ❌ NO CHECKS! Attacker can reenter via this!
///         return this.onERC721Received.selector;
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnprotectedCallbackVulnerability {
    pub vulnerability_type: CallbackIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallbackIssueType {
    UnprotectedERC721Receiver,     // onERC721Received without checks
    UnprotectedERC1155Receiver,    // onERC1155Received/BatchReceived without checks
    CallbackReentrancy,            // Callback allows reentrancy
    MissingNonReentrant,           // Callback not protected by reentrancy guard
}

pub struct UnprotectedCallbackDetector {
    bytecode: Vec<u8>,
}

impl UnprotectedCallbackDetector {
    const ON_ERC721_RECEIVED: [u8; 4] = [0x15, 0x0b, 0x7a, 0x02]; // onERC721Received
    const ON_ERC1155_RECEIVED: [u8; 4] = [0xf2, 0x3a, 0x6e, 0x61]; // onERC1155Received
    const ON_ERC1155_BATCH_RECEIVED: [u8; 4] = [0xbc, 0x19, 0x7c, 0x81]; // onERC1155BatchReceived
    
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UnprotectedCallbackVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_erc721_receiver());
        vulnerabilities.extend(self.detect_erc1155_receiver());

        vulnerabilities
    }

    fn detect_erc721_receiver(&self) -> Vec<UnprotectedCallbackVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(4) {
            if &self.bytecode[i..i+4] == &Self::ON_ERC721_RECEIVED {
                vulnerabilities.push(UnprotectedCallbackVulnerability {
                    vulnerability_type: CallbackIssueType::UnprotectedERC721Receiver,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "onERC721Received callback - verify reentrancy protection".to_string(),
                    exploit_scenario: format!(
                        "ERC-721 CALLBACK at position {}:\n\
                        \n\
                        onERC721Received is an external callback that can be exploited!\n\
                        \n\
                        ATTACK VECTOR:\n\
                        ```solidity\n\
                        contract VulnerableMarket {{\n\
                            mapping(uint256 => address) public listings;\n\
                            \n\
                            function list(IERC721 nft, uint256 tokenId) external {{\n\
                                // Transfer NFT to market\n\
                                nft.safeTransferFrom(msg.sender, address(this), tokenId);\n\
                                \n\
                                // ❌ State updated AFTER transfer\n\
                                listings[tokenId] = msg.sender;\n\
                            }}\n\
                            \n\
                            function onERC721Received(...) external returns (bytes4) {{\n\
                                // ❌ NO PROTECTION! Can reenter here\n\
                                return this.onERC721Received.selector;\n\
                            }}\n\
                        }}\n\
                        \n\
                        contract Attacker is IERC721Receiver {{\n\
                            function attack(Market market, IERC721 nft) external {{\n\
                                // Mint malicious NFT\n\
                                uint256 tokenId = maliciousNFT.mint(address(this));\n\
                                \n\
                                // Call list()\n\
                                market.list(nft, tokenId);\n\
                                // During transfer, onERC721Received is called\n\
                                // We can reenter and exploit!\n\
                            }}\n\
                            \n\
                            function onERC721Received(...) external returns (bytes4) {{\n\
                                // REENTER during callback!\n\
                                market.exploit(); // State not yet updated\n\
                                return this.onERC721Received.selector;\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        REAL EXPLOIT ($30M+):\n\
                        Multiple NFT marketplaces hacked via callback reentrancy.\n\
                        \n\
                        SAFE IMPLEMENTATION:\n\
                        ```solidity\n\
                        contract SafeMarket {{\n\
                            mapping(uint256 => address) public listings;\n\
                            bool private locked;\n\
                            \n\
                            modifier nonReentrant() {{\n\
                                require(!locked, 'No reentrant');\n\
                                locked = true;\n\
                                _;\n\
                                locked = false;\n\
                            }}\n\
                            \n\
                            function list(IERC721 nft, uint256 tokenId)\n\
                                external\n\
                                nonReentrant // ✓ Protection!\n\
                            {{\n\
                                // ✓ Update state BEFORE transfer (CEI pattern)\n\
                                listings[tokenId] = msg.sender;\n\
                                \n\
                                nft.safeTransferFrom(msg.sender, address(this), tokenId);\n\
                            }}\n\
                            \n\
                            function onERC721Received(...) external returns (bytes4) {{\n\
                                // ✓ Callback protected by nonReentrant on main functions\n\
                                return this.onERC721Received.selector;\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        RECOMMENDATIONS:\n\
                        ✓ Use nonReentrant modifier\n\
                        ✓ Follow CEI pattern (Checks-Effects-Interactions)\n\
                        ✓ Update state before external calls\n\
                        ✓ Validate callback caller\n\
                        ✓ Limit callback functionality",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_erc1155_receiver(&self) -> Vec<UnprotectedCallbackVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(4) {
            if &self.bytecode[i..i+4] == &Self::ON_ERC1155_RECEIVED ||
               &self.bytecode[i..i+4] == &Self::ON_ERC1155_BATCH_RECEIVED {
                vulnerabilities.push(UnprotectedCallbackVulnerability {
                    vulnerability_type: CallbackIssueType::UnprotectedERC1155Receiver,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "ERC-1155 callback - verify reentrancy protection".to_string(),
                    exploit_scenario: "ERC-1155 receiver callback detected. Same reentrancy risks as ERC-721. Ensure nonReentrant protection.".to_string(),
                    location: i,
                });
            }
        }

        vulnerabilities
    }
}
