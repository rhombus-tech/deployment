use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainMevVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossDomainMevExtractionDetector {
    bytecode: Vec<u8>,
}

impl CrossDomainMevExtractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossDomainMevVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_l1_l2_arbitrage_atomicity());
        vulnerabilities.extend(self.detect_cross_chain_frontrunning());
        vulnerabilities.extend(self.detect_bridge_mev_extraction());

        vulnerabilities
    }

    fn detect_l1_l2_arbitrage_atomicity(&self) -> Vec<CrossDomainMevVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (cross-domain message)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_bridge_call = window.iter().any(|&b| b == 0x20); // KECCAK256 (message hash)
                let has_price_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                
                if has_bridge_call && has_price_check {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_atomicity_guarantee = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let has_timeout_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_atomicity_guarantee {
                        vulns.push(CrossDomainMevVulnerability {
                            pc,
                            vulnerability_type: "L1L2ArbitrageAtomicity".to_string(),
                            description: format!(
                                "Cross-domain arbitrage at PC {} lacks atomicity protection. Attack: observe price difference between L1 DEX (Uniswap) and L2 DEX \
                                (Optimism/Arbitrum Uniswap), initiate L1→L2 bridge, execute L2 arbitrage, but transactions non-atomic - L2 price may change during \
                                bridge delay (minutes to hours), L1 transaction may fail after L2 committed. MEV searchers can frontrun L2 leg. Missing: atomic \
                                cross-domain execution guarantee, price deviation limits, slippage protection across chains. Should use cross-chain atomic swaps or \
                                conditional execution with refunds.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_cross_chain_frontrunning(&self) -> Vec<CrossDomainMevVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (cross-chain message data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_message_execution = window.iter().any(|&b| b == 0xF1); // CALL
                let has_state_update = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_message_execution && has_state_update {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_nonce_check = pre_window.iter().any(|&b| b == 0x14); // EQ
                    let has_signature_verification = pre_window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_nonce_check {
                        vulns.push(CrossDomainMevVulnerability {
                            pc,
                            vulnerability_type: "CrossChainFrontrunning".to_string(),
                            description: format!(
                                "Cross-chain message execution at PC {} vulnerable to frontrunning. Attack: user initiates cross-chain swap on L1 (Ethereum → Polygon), \
                                message relayed to L2, MEV bot observes relayed message in L2 mempool before execution, frontruns with own swap on L2 DEX, manipulates \
                                price before user's swap executes. Missing: message ordering guarantees, commit-reveal for cross-chain intents, frontrunning protection. \
                                Should use: encrypted cross-chain messages or time-locked execution on destination chain.",
                                pc
                            ),
                            confidence: 0.84,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_bridge_mev_extraction(&self) -> Vec<CrossDomainMevVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (bridge state update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_deposit_logic = window.iter().any(|&b| b == 0x01); // ADD (deposit)
                let has_withdrawal_logic = window.iter().any(|&b| b == 0x03); // SUB (withdrawal)
                
                if (has_deposit_logic || has_withdrawal_logic) {
                    let has_exchange_rate = window.iter().any(|&b| b == 0x04); // DIV (rate calculation)
                    let has_oracle = window.iter().any(|&b| b == 0xFA); // STATICCALL (price oracle)
                    
                    if has_exchange_rate && !has_oracle {
                        vulns.push(CrossDomainMevVulnerability {
                            pc,
                            vulnerability_type: "BridgeMevExtraction".to_string(),
                            description: format!(
                                "Bridge exchange rate at PC {} calculated without oracle validation. Attack: canonical bridge uses on-chain AMM for L1↔L2 token \
                                exchange rate, MEV bot observes large pending bridge deposit, frontruns on source chain AMM to manipulate exchange rate favorably, \
                                bridge processes deposit at manipulated rate, user gets worse rate, MEV bot backriruns to restore price and profit. Missing: external \
                                oracle for exchange rates, TWAP instead of spot price, maximum rate deviation per block. Should use Chainlink or other oracle to \
                                validate on-chain prices before bridge operations.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
