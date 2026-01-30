use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactStateVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ReactStateManagementTransactionReplayDetector {
    bytecode: Vec<u8>,
}

impl ReactStateManagementTransactionReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ReactStateVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_stale_state_transaction_replay());
        vulnerabilities.extend(self.detect_race_condition_double_submission());
        vulnerabilities.extend(self.detect_nonce_desynchronization());

        vulnerabilities
    }

    fn detect_stale_state_transaction_replay(&self) -> Vec<ReactStateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (nonce check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_transaction_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_transaction_execution {
                    let validates_nonce_freshness = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let increments_nonce = window.iter().any(|&b| b == 0x01); // ADD
                    
                    if !validates_nonce_freshness {
                        vulns.push(ReactStateVulnerability {
                            pc,
                            vulnerability_type: "StaleStateTransactionReplay".to_string(),
                            description: format!(
                                "Transaction execution at PC {} uses potentially stale state. Attack: React dApp caches blockchain state (nonce, balance), user triggers transaction, \
                                state updates async, transaction built with stale nonce, causes replay or failure. Stale state flow: (1) React component loads nonce=5 from chain, (2) \
                                stores in useState, (3) user clicks 'Send', (4) component builds transaction with nonce=5, (5) meanwhile another transaction from different tab executed with \
                                nonce=5, (6) chain nonce now=6, (7) new transaction with nonce=5 rejected or replayed if signed. Example: user has DeFi dashboard open, executes swap in one \
                                tab (nonce=10), switches to another tab of same dApp still showing nonce=10, tries to send tokens, transaction fails 'nonce too low'. Or worse: stale balance \
                                shown, user approves transaction thinking they have funds, transaction fails costing gas. Missing: real-time state sync, nonce re-query before transaction, \
                                optimistic UI updates. Should implement: always fetch fresh nonce immediately before transaction construction (await provider.getTransactionCount('pending')), \
                                invalidate cached state on transaction broadcast, use React Query with staleTime=0 for critical data.",
                                pc
                            ),
                            confidence: 0.85,
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

    fn detect_race_condition_double_submission(&self) -> Vec<ReactStateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (transaction submission)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_interaction = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_user_interaction {
                    let prevents_double_click = window.iter().filter(|&&b| b == 0x54).count() >= 2; // SLOAD (submission flag)
                    let has_transaction_lock = window.iter().any(|&b| b == 0x55); // SSTORE (lock)
                    
                    if !prevents_double_click {
                        vulns.push(ReactStateVulnerability {
                            pc,
                            vulnerability_type: "RaceConditionDoubleSubmission".to_string(),
                            description: format!(
                                "Transaction submission at PC {} vulnerable to race condition double-submission. Attack: React button onClick handler not debounced, user double-clicks, \
                                sends two identical transactions before first confirmed. Double-submission: (1) user clicks 'Swap' button, (2) onClick fires, builds & signs transaction, (3) \
                                button still enabled because state update pending, (4) impatient user clicks again, (5) second onClick fires with same parameters, (6) two identical transactions \
                                submitted. Example: user swaps 1 ETH for USDC, double-clicks, sends two 1 ETH swaps, loses 2 ETH instead of 1. Or: NFT mint button, user clicks twice, mints 2 \
                                NFTs paying twice. Real issue: React setState is async, button doesn't disable immediately. Missing: optimistic UI locking, request deduplication, idempotency keys. \
                                Should implement: disable button immediately on click (before async setState), track pending transactions in ref (useRef to avoid closure staleness), add loading \
                                state, implement transaction queue to prevent concurrent submissions.",
                                pc
                            ),
                            confidence: 0.87,
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

    fn detect_nonce_desynchronization(&self) -> Vec<ReactStateVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x01 { // ADD (nonce increment)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_nonce_tracking = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_nonce_tracking {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let syncs_with_chain = forward.iter().any(|&b| b == 0xFA); // STATICCALL (getTransactionCount)
                    let handles_pending_nonces = window.iter().filter(|&&b| b == 0x01).count() >= 2;
                    
                    if !syncs_with_chain {
                        vulns.push(ReactStateVulnerability {
                            pc,
                            vulnerability_type: "NonceDesynchronization".to_string(),
                            description: format!(
                                "Nonce management at PC {} doesn't sync with on-chain state. Attack: dApp maintains local nonce counter, gets out of sync with chain, causes transaction \
                                failures or nonce gaps. Desync scenarios: (1) dApp increments local nonce after transaction send, transaction fails/reverts, local nonce off by 1, all \
                                future transactions rejected, (2) user has multiple dApp tabs open, each tracking nonce independently, both send transaction with same nonce, one fails, (3) \
                                external transaction from wallet, dApp unaware, local nonce stale. Example: user sends token transfer (nonce=10), transaction reverts due to insufficient gas, \
                                dApp increments nonce to 11, next transaction uses nonce=11, chain expects nonce=10, transaction stuck. Or: user sends transaction via MetaMask directly \
                                (nonce=10), dApp still thinks nonce=9, next dApp transaction uses nonce=9, fails 'nonce too low'. Missing: chain nonce reconciliation, pending transaction \
                                tracking, nonce reset on error. Should implement: query chain for nonce including pending transactions (provider.getTransactionCount(address, 'pending')), \
                                reset local nonce on transaction error, use nonce manager library (ethers.NonceManager), listen to accountsChanged event and refresh nonce.",
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
}
