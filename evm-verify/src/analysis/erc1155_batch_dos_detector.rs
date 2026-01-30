/// ERC-1155 Batch DoS Vulnerability Detector
///
/// Detects DoS attacks via ERC-1155 batch operations with huge arrays.
/// safeBatchTransferFrom allows transferring multiple tokens - unbounded loops = DoS.
///
/// Why dangerous:
/// - Batch operations process arrays in loops
/// - No size limits → attacker sends huge array
/// - Each iteration costs gas
/// - onERC1155BatchReceived callback per item
/// - Out-of-gas → entire batch reverts
///
/// Attack vectors:
/// - Marketplace listings with 1000s of tokens
/// - Batch transfers that consume all gas
/// - Callback loops that never complete
/// - Griefing attacks blocking legitimate transfers
///
/// Real exploits:
/// - Multiple NFT marketplace DoS
/// - $5M+ in locked assets
/// - OpenSea batch transfer issues
/// - Rarible marketplace griefing
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableMarketplace {
///     function batchList(
///         uint256[] calldata tokenIds,
///         uint256[] calldata amounts
///     ) external {
///         // ❌ NO SIZE CHECK!
///         for (uint i = 0; i < tokenIds.length; i++) {
///             nft.safeTransferFrom(
///                 msg.sender,
///                 address(this),
///                 tokenIds[i],
///                 amounts[i],
///                 ""
///             );
///         }
///     }
/// }
/// // Attack: Call with 10,000 element array → out of gas!
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ERC1155BatchDosVulnerability {
    pub vulnerability_type: ERC1155BatchIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC1155BatchIssueType {
    UnboundedBatchTransfer,        // safeBatchTransferFrom without size check
    BatchCallbackLoop,             // onERC1155BatchReceived in loop
    LargeArrayIteration,           // Iterating large arrays without limit
    NestedBatchOperations,         // Batch within batch
}

pub struct ERC1155BatchDosDetector {
    bytecode: Vec<u8>,
}

impl ERC1155BatchDosDetector {
    // ERC-1155 function selectors
    const SAFE_BATCH_TRANSFER_FROM: [u8; 4] = [0x2e, 0xb2, 0xc2, 0xd6]; // safeBatchTransferFrom
    const ON_ERC1155_BATCH_RECEIVED: [u8; 4] = [0xbc, 0x19, 0x7c, 0x81]; // onERC1155BatchReceived

    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ERC1155BatchDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_batch_operations());
        vulnerabilities.extend(self.detect_array_iteration());

        vulnerabilities
    }

    fn detect_batch_operations(&self) -> Vec<ERC1155BatchDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for safeBatchTransferFrom selector
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if &self.bytecode[i..i+4] == &Self::SAFE_BATCH_TRANSFER_FROM {
                vulnerabilities.push(ERC1155BatchDosVulnerability {
                    vulnerability_type: ERC1155BatchIssueType::UnboundedBatchTransfer,
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: "ERC-1155 batch transfer detected - verify array size limits".to_string(),
                    exploit_scenario: format!(
                        "ERC-1155 BATCH DoS at position {}:\n\
                        \n\
                        safeBatchTransferFrom allows transferring multiple tokens at once.\n\
                        WITHOUT size limits, attackers can cause DoS!\n\
                        \n\
                        VULNERABLE PATTERN:\n\
                        ```solidity\n\
                        contract VulnerableNFTMarket {{\n\
                            IERC1155 public nft;\n\
                            \n\
                            function batchList(\n\
                                uint256[] calldata ids,\n\
                                uint256[] calldata amounts,\n\
                                uint256[] calldata prices\n\
                            ) external {{\n\
                                // ❌ NO SIZE CHECK!\n\
                                for (uint i = 0; i < ids.length; i++) {{\n\
                                    // Each iteration:\n\
                                    // - Calls safeTransferFrom\n\
                                    // - Triggers onERC1155Received callback\n\
                                    // - Updates storage\n\
                                    // - Emits events\n\
                                    \n\
                                    nft.safeTransferFrom(\n\
                                        msg.sender,\n\
                                        address(this),\n\
                                        ids[i],\n\
                                        amounts[i],\n\
                                        \"\"\n\
                                    );\n\
                                    \n\
                                    listings[ids[i]] = Listing({{\n\
                                        seller: msg.sender,\n\
                                        amount: amounts[i],\n\
                                        price: prices[i]\n\
                                    }});\n\
                                }}\n\
                            }}\n\
                        }}\n\
                        \n\
                        // ATTACK:\n\
                        uint256[] memory ids = new uint256[](10000);\n\
                        uint256[] memory amounts = new uint256[](10000);\n\
                        uint256[] memory prices = new uint256[](10000);\n\
                        \n\
                        // Fill arrays with valid data\n\
                        for (uint i = 0; i < 10000; i++) {{\n\
                            ids[i] = i;\n\
                            amounts[i] = 1;\n\
                            prices[i] = 1 ether;\n\
                        }}\n\
                        \n\
                        market.batchList(ids, amounts, prices);\n\
                        // OUT OF GAS! Transaction reverts!\n\
                        // Contract unusable for large batches!\n\
                        ```\n\
                        \n\
                        REAL SCENARIO - OPENSEA:\n\
                        ```\n\
                        User tries to list 5000 NFTs at once\n\
                        → Transaction costs 50M gas\n\
                        → Exceeds block gas limit (30M)\n\
                        → Always reverts\n\
                        → User cannot list their NFTs\n\
                        → Funds effectively locked\n\
                        ```\n\
                        \n\
                        CALLBACK AMPLIFICATION:\n\
                        ```solidity\n\
                        contract MaliciousReceiver is IERC1155Receiver {{\n\
                            function onERC1155BatchReceived(\n\
                                address,\n\
                                address,\n\
                                uint256[] memory ids,\n\
                                uint256[] memory amounts,\n\
                                bytes memory\n\
                            ) external returns (bytes4) {{\n\
                                // ❌ ATTACK: Expensive operations\n\
                                for (uint i = 0; i < ids.length; i++) {{\n\
                                    // Consume all available gas\n\
                                    for (uint j = 0; j < 1000; j++) {{\n\
                                        keccak256(abi.encode(i, j));\n\
                                    }}\n\
                                }}\n\
                                return this.onERC1155BatchReceived.selector;\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        SAFE IMPLEMENTATION:\n\
                        ```solidity\n\
                        contract SafeNFTMarket {{\n\
                            uint256 constant MAX_BATCH_SIZE = 100;\n\
                            \n\
                            function batchList(\n\
                                uint256[] calldata ids,\n\
                                uint256[] calldata amounts,\n\
                                uint256[] calldata prices\n\
                            ) external {{\n\
                                // ✓ SIZE CHECK\n\
                                require(\n\
                                    ids.length <= MAX_BATCH_SIZE,\n\
                                    'Batch too large'\n\
                                );\n\
                                require(\n\
                                    ids.length == amounts.length &&\n\
                                    ids.length == prices.length,\n\
                                    'Length mismatch'\n\
                                );\n\
                                \n\
                                // Safe to iterate\n\
                                for (uint i = 0; i < ids.length; i++) {{\n\
                                    nft.safeTransferFrom(\n\
                                        msg.sender,\n\
                                        address(this),\n\
                                        ids[i],\n\
                                        amounts[i],\n\
                                        \"\"\n\
                                    );\n\
                                    \n\
                                    listings[ids[i]] = Listing({{\n\
                                        seller: msg.sender,\n\
                                        amount: amounts[i],\n\
                                        price: prices[i]\n\
                                    }});\n\
                                }}\n\
                            }}\n\
                        }}\n\
                        ```\n\
                        \n\
                        BEST PRACTICES:\n\
                        ✓ Limit batch size (50-200 items)\n\
                        ✓ Gas estimations for max batch\n\
                        ✓ Validate array lengths match\n\
                        ✓ Consider pagination for large sets\n\
                        ✓ Test with maximum size batches\n\
                        \n\
                        SEVERITY: HIGH\n\
                        - DoS entire marketplace\n\
                        - Lock user funds\n\
                        - Griefing attacks\n\
                        - Block gas limit issues",
                        i
                    ),
                    location: i,
                });
            }
        }

        vulnerabilities
    }

    fn detect_array_iteration(&self) -> Vec<ERC1155BatchDosVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for CALLDATALOAD in loops (array access pattern)
        let mut in_loop = false;
        let mut loop_has_calldataload = false;

        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0x5B => { // JUMPDEST (potential loop start)
                    in_loop = true;
                    loop_has_calldataload = false;
                }
                0x35 if in_loop => { // CALLDATALOAD in loop
                    loop_has_calldataload = true;
                }
                0x56 | 0x57 if in_loop && loop_has_calldataload => { // JUMP/JUMPI
                    vulnerabilities.push(ERC1155BatchDosVulnerability {
                        vulnerability_type: ERC1155BatchIssueType::LargeArrayIteration,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.60,
                        description: "Array iteration in loop - verify size bounds".to_string(),
                        exploit_scenario: "Loop iterating over calldata array. Ensure array size is bounded to prevent DoS.".to_string(),
                        location: i,
                    });
                    in_loop = false;
                }
                _ => {}
            }
        }

        vulnerabilities
    }
}
