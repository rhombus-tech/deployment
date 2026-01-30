use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbasePrimeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CoinbasePrimeCustodySegregationDetector {
    bytecode: Vec<u8>,
}

impl CoinbasePrimeCustodySegregationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CoinbasePrimeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_account_isolation_breach());
        vulnerabilities.extend(self.detect_cross_customer_access());
        vulnerabilities.extend(self.detect_omnibus_account_confusion());

        vulnerabilities
    }

    fn detect_account_isolation_breach(&self) -> Vec<CoinbasePrimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (account balance access)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_balance_operation = window.iter().any(|&b| b == 0x03); // SUB (withdrawal)
                let has_account_identifier = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_balance_operation {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_strict_account_check = pre_window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    let has_namespace_isolation = pre_window.iter().any(|&b| b == 0x20); // KECCAK256 (namespacing)
                    
                    if !has_strict_account_check || !has_namespace_isolation {
                        vulns.push(CoinbasePrimeVulnerability {
                            pc,
                            vulnerability_type: "AccountIsolationBreach".to_string(),
                            description: format!(
                                "Account balance access at PC {} lacks proper isolation. Attack: custody service holds multiple customers' funds in same contract, if account \
                                identifiers not properly validated, one customer could access another's funds. Example: storage layout uses predictable keys like keccak256(accountId, \
                                slot), if accountId not authenticated, attacker provides victim's accountId, reads/modifies their balance. Or: accountId derived from caller address \
                                without signature verification, attacker calls with victim's address. Results in: cross-customer theft, balance manipulation, accounting corruption. \
                                Real risk: Coinbase Prime manages institutional funds, breach affects multiple clients. Missing: cryptographic account binding, two-factor authorization, \
                                storage namespacing. Should implement: balances[keccak256(customerPubKey, nonce, contractAddress)], require signature from customer for any access, \
                                use separate contracts or storage namespaces per customer.",
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

    fn detect_cross_customer_access(&self) -> Vec<CoinbasePrimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (transfer/withdrawal)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_amount_transfer = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (amount)
                let has_recipient = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_amount_transfer && has_recipient {
                    let has_source_account_auth = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256
                    let has_destination_validation = window.iter().filter(|&&b| b == 0x14).count() >= 3;
                    
                    if !has_source_account_auth {
                        vulns.push(CoinbasePrimeVulnerability {
                            pc,
                            vulnerability_type: "CrossCustomerAccess".to_string(),
                            description: format!(
                                "Transfer execution at PC {} allows potential cross-customer fund movement. Attack: custody platform should only allow withdrawals from customer's own \
                                account to their authorized addresses, if source account not cryptographically bound to caller, attacker initiates withdrawal from victim's account. \
                                Attack vectors: (1) API key compromise - attacker uses victim's API key to withdraw to own address, (2) account enumeration - attacker guesses victim \
                                accountIds, (3) authorization bypass - transfer function doesn't verify caller owns source account. Example: withdrawal function takes (fromAccount, \
                                toAddress, amount) without verifying fromAccount belongs to msg.sender, attacker calls with victim's accountId. Missing: account ownership verification, \
                                whitelisted withdrawal addresses, multi-approval for large transfers. Should require: msg.sender == accountOwners[fromAccount] || has valid signature \
                                from account owner, toAddress in approvedAddresses[fromAccount], amounts >$10K require 2-of-3 approval.",
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

    fn detect_omnibus_account_confusion(&self) -> Vec<CoinbasePrimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (balance update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_deposit = window.iter().any(|&b| b == 0x47); // SELFBALANCE
                let has_accounting_update = window.iter().filter(|&&b| b == 0x01).count() >= 2; // ADD
                
                if has_deposit && has_accounting_update {
                    let has_reconciliation_check = window.iter().filter(|&&b| b == 0x14).count() >= 3;
                    let tracks_omnibus_vs_individual = window.iter().filter(|&&b| b == 0x54).count() >= 4;
                    
                    if !has_reconciliation_check {
                        vulns.push(CoinbasePrimeVulnerability {
                            pc,
                            vulnerability_type: "OmnibusAccountConfusion".to_string(),
                            description: format!(
                                "Account balance tracking at PC {} vulnerable to omnibus/segregated confusion. Attack: custody uses single omnibus wallet (one contract) with internal \
                                accounting for multiple customers, if deposit attribution wrong or accounting mismatch, one customer's deposit credited to another. Example: Customer A \
                                deposits 100 ETH, deposit event triggers, but accountId parameter corrupted, credited to Customer B. Or: withdrawal from omnibus not properly debited \
                                from customer's internal balance, allows customer to withdraw more than they own, draining other customers' funds. Accounting errors compound: total \
                                omnibus balance = 1000 ETH, sum of customer balances = 1050 ETH due to double-crediting, leads to insolvency. Missing: strict deposit attribution, \
                                balance invariant checking, reconciliation. Should implement: every deposit must specify customer via on-chain memo or off-chain matching, invariant check: \
                                sum(all customer balances) == omnibus wallet balance, automated reconciliation every block.",
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
}
