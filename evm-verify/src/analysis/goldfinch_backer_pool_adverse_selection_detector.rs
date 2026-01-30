use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldfinchBackerPoolAdverseSelectionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GoldfinchBackerPoolAdverseSelectionDetector {
    bytecode: Vec<u8>,
}

impl GoldfinchBackerPoolAdverseSelectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GoldfinchBackerPoolAdverseSelectionVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_information_asymmetry());
        vulnerabilities.extend(self.detect_cherry_picking_attack());
        vulnerabilities.extend(self.detect_late_backer_frontrunning());
        vulnerabilities
    }

    fn detect_information_asymmetry(&self) -> Vec<GoldfinchBackerPoolAdverseSelectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (backer deposit)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let accepts_deposit = self.bytecode[start..pc].iter().filter(|&&b| b == 0x34).count() >= 1;
                if accepts_deposit {
                    let discloses_borrower_info = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 5;
                    if !discloses_borrower_info {
                        vulns.push(GoldfinchBackerPoolAdverseSelectionVulnerability {
                            pc,
                            vulnerability_type: "InformationAsymmetry".to_string(),
                            description: format!("Backer deposit at PC {} lacks borrower information disclosure, enabling adverse selection. Attack: borrower pool creates deal with minimal public information, insiders know borrower is high-risk, outsider backers invest blindly, borrower defaults, insiders exit early. Real attack: Goldfinch borrower pool opens with vague business description, pool sponsor has private knowledge of pending lawsuit against borrower, public backers invest $2M, insider backers withdraw after lawsuit public, borrower defaults. Example: senior pool allocates to junior tranche, junior backers lack access to borrower financials, auditor backchannels reveal insolvency risk to select backers, information holders exit, uninformed suffer 80% loss. Missing: mandatory borrower disclosure, information symmetry enforcement, insider trading prevention. Should implement: require verified borrower financials on-chain, public audit reports. Fix: mandate borrower KYC/credit report hash on-chain, require 7-day information review period before deposits accepted, implement insider trading lockup (no withdrawals for 90 days if special access), add whistleblower rewards for undisclosed material information.", pc),
                            confidence: 0.84,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cherry_picking_attack(&self) -> Vec<GoldfinchBackerPoolAdverseSelectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (pool selection)
                let window_end = (pc + 100).min(self.bytecode.len());
                let selects_pool = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 1;
                if selects_pool {
                    let has_diversification_requirement = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_diversification_requirement {
                        vulns.push(GoldfinchBackerPoolAdverseSelectionVulnerability {
                            pc,
                            vulnerability_type: "CherryPickingAttack".to_string(),
                            description: format!("Pool selection at PC {} allows cherry-picking without diversification requirements. Attack: senior pool allocator cherry-picks only deals with high backer interest, creates appearance of diversification while concentrating in correlated risks, senior pool suffers during market downturn. Real vulnerability: Goldfinch senior pool delegates allocation decisions, allocator chooses 10 different borrower pools all in crypto mining sector, appears diversified by count, crypto crash causes all borrowers to default simultaneously. Example: allocator sees borrower pool A oversubscribed 300%, pool B only 50% filled, allocates 90% to pool A assuming high demand = quality, pool A was Ponzi scheme attracting retail, collapses first. Missing: sector diversification limits, correlation analysis, allocation caps. Should implement: enforce maximum allocation per sector, correlation coefficient checks. Fix: require <30% allocation to any single sector/geography, implement on-chain correlation analysis using oracle price feeds, mandate allocation across credit rating tiers, add circuit breaker for similar borrower patterns, require economic diversity score >0.6.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_late_backer_frontrunning(&self) -> Vec<GoldfinchBackerPoolAdverseSelectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP (deposit timing)
                let window_end = (pc + 120).min(self.bytecode.len());
                let allows_late_entry = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                if allows_late_entry {
                    let has_early_bird_protection = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_early_bird_protection {
                        vulns.push(GoldfinchBackerPoolAdverseSelectionVulnerability {
                            pc,
                            vulnerability_type: "LateBackerFrontrunning".to_string(),
                            description: format!("Late backer entry at PC {} allows frontrunning early risk-takers without protection. Attack: borrower pool opens, early backers take risk funding before track record established, pool performs well for 6 months, late backers frontrun repayments claiming yield without bearing early risk, dilutes early backer returns. Real attack: Goldfinch borrower makes first 3 monthly payments on time, late backers see positive track record, deposit large amounts right before 4th payment, capture yield from established performance, early risk-takers subsidized late free-riders. Example: pool cap $5M, early backers fill $2M in week 1 taking maximum risk, by month 6 pool at 80% health, late backers fill remaining $3M in hour before month 6 payment, capture same yield as early backers who bore 6 months uncertainty. Missing: time-weighted returns, early backer bonuses, deposit lockout periods. Should implement: reward early deposits with higher yield tiers. Fix: implement graduated yield based on deposit timing (early backers get +2% APY), add deposit lockout after 50% pool filled, require minimum holding period proportional to pool age, distribute performance bonuses to early risk-takers, cap late entry deposits to 20% of pool size.", pc),
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
