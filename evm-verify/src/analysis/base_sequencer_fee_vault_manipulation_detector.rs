use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseSequencerFeeVaultVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BaseSequencerFeeVaultManipulationDetector {
    bytecode: Vec<u8>,
}

impl BaseSequencerFeeVaultManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BaseSequencerFeeVaultVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unchecked_l1_base_fee());
        vulnerabilities.extend(self.detect_fee_vault_withdrawal_frontrun());
        vulnerabilities.extend(self.detect_priority_fee_manipulation());
        vulnerabilities
    }

    fn detect_unchecked_l1_base_fee(&self) -> Vec<BaseSequencerFeeVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x48 { // BASEFEE
                let window_end = (pc + 80).min(self.bytecode.len());
                let validates_fee = self.bytecode[pc..window_end].iter().any(|&b| b == 0x10);
                if !validates_fee {
                    vulns.push(BaseSequencerFeeVaultVulnerability {
                        pc, vulnerability_type: "UncheckedL1BaseFee".to_string(),
                        description: format!("Base chain base fee read at PC {} doesn't validate against L1 fees, allowing sequencer fee manipulation. Attack: Base L2 sequencer sets artificially low basefee, users pay less to sequencer but L1 data availability costs remain high, sequencer loses money or protocol subsidizes. Real vulnerability: basefee on Base reflects sequencer costs, not L1 DA costs, protocols trusting basefee for gas estimation underpay. Example: protocol estimates L1 submission cost using basefee*gasUsed, sequencer manipulates basefee down 90%, protocol submits to L1 paying 10x expected, drains protocol funds. Missing: query L1GASPRICE oracle (0x420000000000000000000000000000000000000F) for real L1 costs. Should implement: l1GasPrice = IL1Block(0x4200..0F).basefee(), totalCost = l2Gas*basefee + l1Gas*l1GasPrice. Fix: never trust basefee alone on L2, always check L1 gas oracle.", pc),
                        confidence: 0.86,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_fee_vault_withdrawal_frontrun(&self) -> Vec<BaseSequencerFeeVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (withdrawal from fee vault)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let reads_balance = self.bytecode[start..pc].iter().any(|&b| b == 0x31);
                if reads_balance {
                    let has_minimum_threshold = self.bytecode[start..pc].iter().any(|&b| b == 0x10);
                    if !has_minimum_threshold {
                        vulns.push(BaseSequencerFeeVaultVulnerability {
                            pc, vulnerability_type: "FeeVaultWithdrawalFrontrun".to_string(),
                            description: format!("Fee vault withdrawal at PC {} lacks minimum threshold, allowing frontrun extraction. Attack: protocol monitors SequencerFeeVault balance, when threshold reached calls withdraw(), sequencer frontruns with own withdrawal. Real scenario: BaseFeeVault accumulates 10 ETH fees, protocol's withdraw transaction in mempool, sequencer sees it, frontruns with higher priority fee paying self first. Example: SequencerFeeVault.withdraw() callable by anyone when balance > MIN_WITHDRAWAL_AMOUNT, attacker monitors mempool, frontruns legitimate withdrawal stealing accumulated fees. Missing: access control on withdrawal, time-lock, or withdrawal queue. Fix: implement onlyOwner on withdraw() or RECIPIENT immutable variable, use MIN_WITHDRAWAL_AMOUNT with time-based anti-frontrun delay.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_priority_fee_manipulation(&self) -> Vec<BaseSequencerFeeVaultVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x33 { // CALLER (tx.origin check for sequencer)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_fee_calculation = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x02).count() >= 2;
                if has_fee_calculation {
                    let validates_priority_fee = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !validates_priority_fee {
                        vulns.push(BaseSequencerFeeVaultVulnerability {
                            pc, vulnerability_type: "PriorityFeeManipulation".to_string(),
                            description: format!("Fee calculation at PC {} trusts priority fee without validation, sequencer can manipulate. Attack: Base sequencer controls transaction ordering, sets own transactions' priority fees artificially high to extract MEV without cost. Real attack: sequencer sandwich attack with maxPriorityFeePerGas = 1000 gwei, but sequencer doesn't actually pay themselves priority fee, profits from sandwich without fee cost. Example: protocol calculates fair ordering using priority fee as signal, sequencer manipulates priority fees to control ordering for free. Missing: validate sequencer isn't tx.origin, or cap priority fee impact on ordering. Should implement: if (msg.sender == SEQUENCER_ADDRESS) revert PriorityFeeInvalid(). Fix: don't trust priority fees on centralized L2s for critical logic, use alternative fairness mechanisms like time-based ordering.", pc),
                            confidence: 0.78,
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
