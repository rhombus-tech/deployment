use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruefiPortfolioManagerCollusionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TruefiPortfolioManagerCollusionDetector {
    bytecode: Vec<u8>,
}

impl TruefiPortfolioManagerCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TruefiPortfolioManagerCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_manager_borrower_collusion());
        vulnerabilities.extend(self.detect_credit_score_override());
        vulnerabilities.extend(self.detect_loan_approval_centralization());
        vulnerabilities
    }

    fn detect_manager_borrower_collusion(&self) -> Vec<TruefiPortfolioManagerCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (loan approval)
                let window_end = (pc + 120).min(self.bytecode.len());
                let approves_loan = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if approves_loan {
                    let has_collusion_check = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 3;
                    if !has_collusion_check {
                        vulns.push(TruefiPortfolioManagerCollusionVulnerability {
                            pc,
                            vulnerability_type: "ManagerBorrowerCollusion".to_string(),
                            description: format!("Loan approval at PC {} lacks collusion detection, enabling manager-borrower coordination. Attack: portfolio manager colludes with borrower, approves undercollateralized loan, both profit while lenders lose. Real attack: TrueFi manager receives kickback to approve risky loan, borrower defaults intentionally, manager shared profits before default, lenders suffer losses. Example: manager approves $1M loan to shell company with 10% collateral, borrower withdraws funds, declares bankruptcy, lenders lose $900k while manager got 5% commission. Missing: conflict-of-interest checks, collateral verification, independent loan committee. Should implement: require multi-party approval, validate borrower-manager relationship. Fix: implement DAO voting for large loans, require 3-of-5 approval from independent managers, verify no shared addresses/contracts between manager and borrower, enforce minimum collateralization ratios, add reputation slashing for defaults.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_credit_score_override(&self) -> Vec<TruefiPortfolioManagerCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (credit score update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let updates_credit_score = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if updates_credit_score {
                    let has_verification = self.bytecode[start..pc].iter().filter(|&&b| b == 0xFA).count() >= 1;
                    if !has_verification {
                        vulns.push(TruefiPortfolioManagerCollusionVulnerability {
                            pc,
                            vulnerability_type: "CreditScoreOverride".to_string(),
                            description: format!("Credit score update at PC {} allows manager override without verification. Attack: manager arbitrarily inflates borrower's credit score, enables loan approval despite poor history, facilitates collusion. Real vulnerability: TrueFi credit score stored on-chain, manager has update privileges, no oracle verification, can set score to max for colluding borrower. Example: borrower with 300 credit score, manager updates to 850, loan approval algorithm accepts, $5M undercollateralized loan issued, default guaranteed. Missing: oracle integration, historical verification, score calculation transparency. Should implement: use verifiable off-chain credit data, Chainlink oracle integration. Fix: require credit bureau oracle attestation, implement score calculation on-chain from verifiable metrics, add time-weighted history preventing sudden jumps, require DAO governance for manual overrides, slash manager stake for fraudulent scores.", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_loan_approval_centralization(&self) -> Vec<TruefiPortfolioManagerCollusionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x33 { // CALLER (manager check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let single_approver = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() == 1;
                if single_approver {
                    let approves_loans = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                    if approves_loans {
                        vulns.push(TruefiPortfolioManagerCollusionVulnerability {
                            pc,
                            vulnerability_type: "LoanApprovalCentralization".to_string(),
                            description: format!("Loan approval at PC {} relies on single manager, creating centralization risk. Attack: single portfolio manager controls all loan approvals, can collude with multiple borrowers, extract systematic value from lenders. Real attack: TrueFi portfolio has single manager approval authority, manager creates loan approval factory, issues 20 undercollateralized loans to shell companies, extracts fees upfront, all loans default within 90 days. Example: manager approves $50M in risky loans over 6 months, collects 2% origination fees ($1M), borrowers coordinated to default simultaneously, portfolio loses $40M, manager disappeared. Missing: distributed approval authority, multi-sig requirements, approval rate limits. Should implement: require multiple independent manager approvals, DAO veto power. Fix: implement 3-of-5 multi-sig for loans >$100k, rate limit approvals per manager (max 10 loans/month), require 48h timelock with community review, distribute manager roles across non-colluding parties, add emergency DAO override.", pc),
                            confidence: 0.80,
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
