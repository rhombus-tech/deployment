use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolSnipingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MempoolSnipingBotRpcEndpointAbuseDetector {
    bytecode: Vec<u8>,
}

impl MempoolSnipingBotRpcEndpointAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MempoolSnipingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_pending_transaction_exposure());
        vulnerabilities.extend(self.detect_rpc_rate_limit_bypass());
        vulnerabilities.extend(self.detect_private_mempool_leak());

        vulnerabilities
    }

    fn detect_pending_transaction_exposure(&self) -> Vec<MempoolSnipingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (transaction execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_swap_logic = window.iter().filter(|&&b| b == 0x02).count() >= 2; // MUL
                let has_price_calculation = window.iter().any(|&b| b == 0x04); // DIV
                
                if has_swap_logic {
                    let has_frontrun_protection = window.iter().filter(|&&b| b == 0x42).count() >= 2; // TIMESTAMP checks
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 3; // KECCAK256
                    
                    if !has_frontrun_protection && !has_commit_reveal {
                        vulns.push(MempoolSnipingVulnerability {
                            pc,
                            vulnerability_type: "PendingTransactionExposure".to_string(),
                            description: format!(
                                "Swap execution at PC {} exposes pending transactions to mempool sniping. Attack: bots monitor public mempool via eth_newPendingTransactions RPC, \
                                detect profitable transactions (large swaps, NFT mints), front-run with higher gas. Snipe targets: (1) DEX swaps - bot sees 1M USDC->ETH swap, front-runs \
                                to buy ETH before, back-runs to sell after, (2) NFT mints - bot sees mint transaction, copies calldata, submits with higher gas, (3) liquidations - bot \
                                spots liquidation tx, front-runs to claim bounty. Example: user submits swap with 1 gwei gas, bot sees in mempool, submits same swap with 100 gwei, \
                                bot's transaction executes first. Tools: flashbots, bloxroute, Eden network provide mempool monitoring. Missing: private transaction submission, slippage \
                                protection, commit-reveal scheme. Should use: flashbots protect RPC (private mempool), set maxSlippage to limit frontrun profit, or use commit-reveal: \
                                submit hash first, reveal after block inclusion.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_rpc_rate_limit_bypass(&self) -> Vec<MempoolSnipingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (rate limit check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_request_handling = window.iter().any(|&b| b == 0xFA); // STATICCALL
                
                if has_request_handling {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let enforces_per_address_limit = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    let has_ip_tracking = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !enforces_per_address_limit {
                        vulns.push(MempoolSnipingVulnerability {
                            pc,
                            vulnerability_type: "RpcRateLimitBypass".to_string(),
                            description: format!(
                                "RPC endpoint rate limiting at PC {} bypassable. Attack: mempool sniping bots spam eth_newPendingTransactions subscriptions to maximize coverage, if \
                                rate limits weak, bot gains advantage. Bypass techniques: (1) rotate IP addresses via proxy network, (2) use multiple RPC providers (Infura, Alchemy, \
                                QuickNode), (3) run own nodes for unlimited access. Example: Infura limits 100K requests/day, bot uses 100 API keys = 10M requests/day. Or: bot runs \
                                10 archive nodes for direct mempool access. Attack impact: bots with better mempool visibility frontrun more transactions, extract more MEV, hurts normal \
                                users. Arms race: sophisticated bots pay for premium RPC access (bloxroute $10K/month), run geographically distributed nodes. Missing: Sybil-resistant \
                                rate limiting, proof-of-stake for API access, IP fingerprinting. Should implement: rate limit by wallet signature (not IP), require stake for high-volume \
                                access, detect and ban bot patterns (100% pending tx subscriptions), use CAPTCHAs for API key generation.",
                                pc
                            ),
                            confidence: 0.83,
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

    fn detect_private_mempool_leak(&self) -> Vec<MempoolSnipingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (transaction hash)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_transaction_data = window.iter().any(|&b| b == 0x37); // CALLDATACOPY
                
                if has_transaction_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let encrypts_transaction = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let validates_relayer = forward.iter().any(|&b| b == 0x14); // EQ
                    
                    if !encrypts_transaction {
                        vulns.push(MempoolSnipingVulnerability {
                            pc,
                            vulnerability_type: "PrivateMempoolLeak".to_string(),
                            description: format!(
                                "Private transaction handling at PC {} may leak to public mempool. Attack: users submit to 'private' mempool (flashbots, Eden), but if relayer \
                                compromised or transaction format detectable, bots can snipe. Leak vectors: (1) malicious flashbots searcher sees bundle, front-runs in public mempool, \
                                (2) transaction metadata leaks intent (e.g., contract address + function selector reveals NFT mint), (3) relayer logs transactions, sells data to bots. \
                                Example: user submits NFT mint to flashbots, searcher in bundle sees target NFT contract, submits competing mint publicly with higher gas. Or: Eden \
                                relay operator colludes with MEV bot, shares private transactions. Consequences: private mempool provides false sense of security, users pay premium fees \
                                but still get front-run. Missing: end-to-end encryption, trusted execution environment, cryptographic privacy. Should use: encrypt transaction until \
                                block inclusion (threshold encryption), use SGX-based relayers (Automata), or commit-reveal with time-lock encryption (drand randomness).",
                                pc
                            ),
                            confidence: 0.81,
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
