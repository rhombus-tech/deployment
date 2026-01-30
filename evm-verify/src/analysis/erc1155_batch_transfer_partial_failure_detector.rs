use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc1155BatchTransferPartialFailureVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Erc1155BatchTransferPartialFailureDetector {
    bytecode: Vec<u8>,
}

impl Erc1155BatchTransferPartialFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Erc1155BatchTransferPartialFailureVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_partial_array_processing());
        vulnerabilities.extend(self.detect_inconsistent_state_on_revert());
        vulnerabilities.extend(self.detect_batch_callback_atomicity());
        vulnerabilities
    }

    fn detect_partial_array_processing(&self) -> Vec<Erc1155BatchTransferPartialFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x57 { // JUMPI (loop in batch transfer)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_array_iteration = self.bytecode[start..pc].iter().filter(|&&b| b == 0x01).count() >= 2;
                if has_array_iteration {
                    let has_balance_update = self.bytecode[start..pc].iter().any(|&b| b == 0x55);
                    if has_balance_update {
                        let window_end = (pc + 80).min(self.bytecode.len());
                        let has_revert_on_fail = self.bytecode[pc..window_end].iter().any(|&b| b == 0xFD);
                        if !has_revert_on_fail {
                            vulns.push(Erc1155BatchTransferPartialFailureVulnerability {
                                pc, vulnerability_type: "PartialArrayProcessing".to_string(),
                                description: format!("Batch transfer loop at PC {} processes arrays without atomic revert, allows partial completion. Attack: safeBatchTransferFrom([id1, id2, id3], [amt1, amt2, amt3]), transfer succeeds for id1, id2, fails on id3, first two already updated. Real vulnerability: if ids.length != amounts.length caught mid-loop, some balances already modified, inconsistent state. Example: batch transfer 10 token types, 7 succeed, 8th fails insufficient balance, contract doesn't revert all, user loses 7 tokens but recipient only gets partial batch. Missing: validate all conditions before any state changes, or implement full rollback. Should implement: check ids.length == amounts.length upfront, validate all balances sufficient in first pass, then execute transfers. Fix: two-phase commit - validate all, then execute all atomically.", pc),
                                confidence: 0.85,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_inconsistent_state_on_revert(&self) -> Vec<Erc1155BatchTransferPartialFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xFD { // REVERT (in batch operation)
                let start = if pc > 150 { pc - 150 } else { 0 };
                let has_multiple_sstores = self.bytecode[start..pc].iter().filter(|&&b| b == 0x55).count() >= 3;
                if has_multiple_sstores {
                    vulns.push(Erc1155BatchTransferPartialFailureVulnerability {
                        pc, vulnerability_type: "InconsistentStateOnRevert".to_string(),
                        description: format!("Batch operation reverts at PC {} after multiple state modifications, but external calls already made. Attack: safeBatchTransferFrom updates balances for 5 tokens, calls onERC1155BatchReceived, callback reverts, balances already modified don't auto-revert if external state changed. Real issue: contract updates internal mapping, emits Transfer events, calls external contract, external contract changes own state based on events, then reverts, events already observed by external contract can't be undone. Example: marketplace batch transfers NFTs, updates balances, external oracle indexes transfers, callback reverts, oracle has stale data. Missing: emit events only after all state changes and callback success. Fix: check callback success before emitting events, or use try/catch for callbacks.", pc),
                        confidence: 0.81,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_batch_callback_atomicity(&self) -> Vec<Erc1155BatchTransferPartialFailureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (onERC1155BatchReceived)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_batch_processing = self.bytecode[start..pc].iter().filter(|&&b| b == 0x57).count() >= 2;
                if has_batch_processing {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let checks_return = self.bytecode[pc..window_end].iter().any(|&b| b == 0x14);
                    if !checks_return {
                        vulns.push(Erc1155BatchTransferPartialFailureVulnerability {
                            pc, vulnerability_type: "BatchCallbackAtomicity".to_string(),
                            description: format!("Batch transfer callback at PC {} doesn't enforce atomicity between balance updates and callback. Attack: balances updated in loop, onERC1155BatchReceived called after, callback can observe partial state. Real vulnerability: safeBatchTransferFrom iterates ids array updating balances one by one, calls callback at end, callback queries balanceOfBatch sees intermediate state. Example: transferring [10 of id=1, 20 of id=2], after first update balance(id=1)=10 but id=2 not yet transferred, callback sees inconsistent state, could trigger unintended logic. Missing: atomic state update before callback, or pass all data to callback without intermediate queries. Fix: update all balances in memory, commit all at once with single SSTORE, then call callback.", pc),
                            confidence: 0.77,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
