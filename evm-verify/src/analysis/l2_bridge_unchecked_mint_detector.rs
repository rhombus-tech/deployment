use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2BridgeUncheckedMintVulnerability {
    pub location: usize,
    pub mint_type: UncheckedMintType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UncheckedMintType {
    MintWithoutBurnProof,            // Mint without verifying L1 burn
    DoubleMintPrevention,            // Same deposit minted twice
    BridgeMessageReplay,             // Bridge message replayed
    MintAmountManipulation,          // Mint amount differs from deposit
    CrossDomainMessengerBypass,      // Bypass messenger validation
    UncheckedL1Origin,               // L1 origin not validated
}

pub struct L2BridgeUncheckedMintDetector {
    bytecode: Vec<u8>,
}

impl L2BridgeUncheckedMintDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<L2BridgeUncheckedMintVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_mint_without_burn_proof() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::MintWithoutBurnProof,
                severity: "Critical".to_string(),
                description: "L2 bridge mints tokens without verifying L1 burn proof. Optimism Wintermute \
                             $20M exploit: unchecked mint allowed creating tokens without deposits. MUST \
                             verify L1 state root and burn event.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_double_mint_prevention() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::DoubleMintPrevention,
                severity: "Critical".to_string(),
                description: "Bridge lacks double-mint prevention. Same L1 deposit can be claimed multiple \
                             times on L2. Must track processed deposits via nonce or hash.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_bridge_message_replay() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::BridgeMessageReplay,
                severity: "Critical".to_string(),
                description: "Cross-chain messages can be replayed. No nonce or replay protection allows \
                             reusing valid bridge messages to mint repeatedly.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_mint_amount_manipulation() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::MintAmountManipulation,
                severity: "High".to_string(),
                description: "Mint amount not validated against L1 deposit. Allows minting more tokens \
                             than deposited by manipulating amount parameter.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_cross_domain_messenger_bypass() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::CrossDomainMessengerBypass,
                severity: "Critical".to_string(),
                description: "Bridge message validation can be bypassed. Does not properly verify message \
                             came from trusted cross-domain messenger contract.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_unchecked_l1_origin() {
            vulnerabilities.push(L2BridgeUncheckedMintVulnerability {
                location: loc,
                mint_type: UncheckedMintType::UncheckedL1Origin,
                severity: "High".to_string(),
                description: "L1 message origin not validated. Allows unauthorized contracts to trigger \
                             minting by impersonating L1 bridge contract.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_mint_without_burn_proof(&self) -> Option<usize> {
        // Mint function without state root verification
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // finalizeBridgeERC20 (0x0166a07a), mint (0x40c10f19)
                if selector == 0x0166a07a || selector == 0x40c10f19 {
                    // Check for state root verification (SHA3 of proof)
                    let mut has_proof_verification = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // SHA3
                            has_proof_verification = true;
                            break;
                        }
                    }
                    if !has_proof_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_double_mint_prevention(&self) -> Option<usize> {
        // Mint without nonce/hash tracking
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x0166a07a || selector == 0x40c10f19 {
                    // Check for deposit hash/nonce storage
                    let mut has_replay_protection = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        // Look for SSTORE (storing processed deposit)
                        if self.bytecode[j] == 0x55 {
                            // Check if preceded by hash (SHA3)
                            for k in j.saturating_sub(20)..j {
                                if self.bytecode[k] == 0x20 {
                                    has_replay_protection = true;
                                    break;
                                }
                            }
                            if has_replay_protection {
                                break;
                            }
                        }
                    }
                    if !has_replay_protection {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_bridge_message_replay(&self) -> Option<usize> {
        // Message handling without nonce check
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // relayMessage or similar
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x8ef1332e || selector == 0x3dbb202b { // relayMessage
                    // Check for nonce validation
                    let mut has_nonce_check = false;
                    for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                        // SLOAD followed by comparison (checking nonce)
                        if self.bytecode[j] == 0x54 {
                            for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                                if matches!(self.bytecode[k], 0x10 | 0x11 | 0x14) {
                                    has_nonce_check = true;
                                    break;
                                }
                            }
                            if has_nonce_check {
                                break;
                            }
                        }
                    }
                    if !has_nonce_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_mint_amount_manipulation(&self) -> Option<usize> {
        // Mint amount from calldata without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD (amount)
                // Check if used in mint without bounds check
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                        let sel = u32::from_be_bytes([
                            self.bytecode[j + 1],
                            self.bytecode[j + 2],
                            self.bytecode[j + 3],
                            self.bytecode[j + 4],
                        ]);
                        if sel == 0x40c10f19 { // mint
                            // Check for amount validation between CALLDATALOAD and mint
                            let mut has_amount_check = false;
                            for k in i..j {
                                if matches!(self.bytecode[k], 0x10 | 0x11) {
                                    has_amount_check = true;
                                    break;
                                }
                            }
                            if !has_amount_check {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_cross_domain_messenger_bypass(&self) -> Option<usize> {
        // CALLER check missing in bridge function
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x0166a07a { // finalizeBridgeERC20
                    // Check for CALLER validation (must be messenger)
                    let mut has_caller_check = false;
                    for j in i..std::cmp::min(i + 30, self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 { // CALLER
                            // Check if compared to stored messenger address
                            for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 { // EQ
                                    has_caller_check = true;
                                    break;
                                }
                            }
                            if has_caller_check {
                                break;
                            }
                        }
                    }
                    if !has_caller_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unchecked_l1_origin(&self) -> Option<usize> {
        // Cross-chain message without xDomainMessageSender check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                if selector == 0x0166a07a {
                    // Check for xDomainMessageSender() call
                    let mut has_origin_check = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            // Check if calling xDomainMessageSender (0x6e296e45)
                            for k in j.saturating_sub(15)..j {
                                if self.bytecode[k] == 0x63 && k + 4 < self.bytecode.len() {
                                    let inner_sel = u32::from_be_bytes([
                                        self.bytecode[k + 1],
                                        self.bytecode[k + 2],
                                        self.bytecode[k + 3],
                                        self.bytecode[k + 4],
                                    ]);
                                    if inner_sel == 0x6e296e45 {
                                        has_origin_check = true;
                                        break;
                                    }
                                }
                            }
                            if has_origin_check {
                                break;
                            }
                        }
                    }
                    if !has_origin_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
