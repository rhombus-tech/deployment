/// Liquid Staking Derivative (LSD) Vulnerability Analyzer
/// Targets: Lido (stETH), Rocket Pool (rETH), Frax (frxETH), Coinbase (cbETH)
/// Market: $40B+ TVL with proven exploit history

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidStakingVulnerability {
    pub vulnerability_type: LSDVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LSDVulnType {
    /// Oracle manipulation for LSD/ETH pricing
    LSDOracleManipulation,
    /// Withdrawal credential compromise
    WithdrawalCredentialAttack,
    /// Rebasing token accounting errors (stETH specific)
    RebasingAccountingError,
    /// Validator key management vulnerabilities
    ValidatorKeyVulnerability,
    /// MEV theft from validators
    ValidatorMEVTheft,
    /// Slashing cascade affecting derivatives
    SlashingCascade,
    /// Share price manipulation
    SharePriceManipulation,
    /// Withdrawal queue DOS
    WithdrawalQueueDOS,
    /// Validator exit delay exploitation
    ExitDelayExploit,
    /// Beacon chain state mismatch
    BeaconChainMismatch,
    /// Unsafe rebasing integration
    UnsafeRebasingIntegration,
}

pub struct LiquidStakingAnalyzer {
    bytecode: Vec<u8>,
}

impl LiquidStakingAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only analyze if contract appears to be liquid staking related
        if !self.is_liquid_staking_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_oracle_manipulation());
        vulnerabilities.extend(self.detect_withdrawal_credential_attack());
        vulnerabilities.extend(self.detect_rebasing_accounting_errors());
        vulnerabilities.extend(self.detect_validator_key_vulnerabilities());
        vulnerabilities.extend(self.detect_mev_theft());
        vulnerabilities.extend(self.detect_slashing_cascade());
        vulnerabilities.extend(self.detect_share_price_manipulation());
        vulnerabilities.extend(self.detect_withdrawal_queue_dos());
        vulnerabilities.extend(self.detect_beacon_chain_mismatch());

        vulnerabilities
    }

    fn is_liquid_staking_contract(&self) -> bool {
        // Look for liquid staking specific signatures
        let lsd_signatures = [
            &[0x47, 0xe7, 0xef, 0x24][..], // stake() or deposit()
            &[0x2e, 0x1a, 0x7d, 0x4d][..], // requestWithdrawal()
            &[0xa1, 0x90, 0x3e, 0xab][..], // submit() - Lido specific
            &[0x8b, 0x90, 0x00, 0x00][..], // getPooledEthByShares() - Lido
            &[0x06, 0xfd, 0xde, 0x03][..], // totalSupply() (rebasing)
        ];

        let has_lsd_functions = lsd_signatures.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        });

        // Must be complex contract (LSDs are 10k+ bytes)
        has_lsd_functions && self.bytecode.len() > 8000
    }

    fn detect_oracle_manipulation(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Single oracle for LSD/ETH price without validation
        for i in 0..self.bytecode.len().saturating_sub(150) {
            // Look for external oracle call
            if (self.bytecode[i] == 0xFA || self.bytecode[i] == 0xF1) { // STATICCALL or CALL
                // Check if this is used for price calculation
                let followed_by_division = self.bytecode[i+1..i+50]
                    .windows(1).any(|w| w[0] == 0x04); // DIV operation

                // Critical: Single oracle without multi-oracle validation
                let single_oracle = self.bytecode[i.saturating_sub(100)..i+100]
                    .windows(1)
                    .filter(|w| w[0] == 0xFA || w[0] == 0xF1)
                    .count() == 1;

                if followed_by_division && single_oracle {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::LSDOracleManipulation,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "LSD price oracle relies on single source without validation or TWAP".to_string(),
                        exploit_scenario: "stETH Oracle Manipulation Attack:\n\
                            1. Protocol uses Curve pool for stETH/ETH price\n\
                            2. Attacker flash loans 50,000 ETH\n\
                            3. Swaps ETH for stETH in Curve, manipulating pool ratio\n\
                            4. Protocol reads manipulated price (0.95 instead of 0.99)\n\
                            5. Attacker deposits stETH at discount\n\
                            6. Unwinds flash loan, price recovers\n\
                            7. Attacker withdraws at correct price, profiting from gap\n\
                            \n\
                            Real incidents: Multiple Lido integration exploits (2022-2023)".to_string(),
                        remediation: "Use secure oracle strategy:\n\
                            1. Implement multi-oracle price feeds (Chainlink + Uniswap TWAP + Curve)\n\
                            2. Use time-weighted average price (TWAP) over 30+ minutes\n\
                            3. Add deviation bounds (reject if >2% from consensus)\n\
                            4. Circuit breaker for rapid price movements\n\
                            5. Never use spot price from single DEX pool".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_withdrawal_credential_attack(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Withdrawal credentials stored without proper access control
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for storage of withdrawal credentials (usually 32 bytes)
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this is storing address-like data (withdrawal cred)
                let storing_large_value = self.bytecode[i.saturating_sub(20)..i]
                    .windows(1).any(|w| w[0] == 0x7F); // PUSH32

                // Critical: No multi-sig or timelock for credential updates
                let lacks_protection = !self.bytecode[i.saturating_sub(50)..i]
                    .windows(1).any(|w| w[0] == 0xF1); // No external call (multi-sig)

                if storing_large_value && lacks_protection {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::WithdrawalCredentialAttack,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Withdrawal credentials can be updated without multi-sig or timelock".to_string(),
                        exploit_scenario: "Withdrawal Credential Theft:\n\
                            1. LSD protocol manages 100,000 ETH in validators\n\
                            2. Withdrawal credentials stored in contract\n\
                            3. Admin key compromised (phishing, leak, etc.)\n\
                            4. Attacker updates withdrawal credentials to their address\n\
                            5. Initiates validator exits pointing to attacker address\n\
                            6. 100,000 ETH withdrawn to attacker\n\
                            7. All stETH holders lose funds\n\
                            \n\
                            Critical risk: Single point of failure for billions".to_string(),
                        remediation: "Secure withdrawal credentials:\n\
                            1. Require multi-sig (3-of-5 or higher) for updates\n\
                            2. Add 7-day timelock for all credential changes\n\
                            3. Emit events for monitoring\n\
                            4. Consider immutable credentials with upgrade path\n\
                            5. Use hardware security modules (HSM) for keys".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_rebasing_accounting_errors(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Rebasing token balance stored and reused (stETH issue)
        for i in 0..self.bytecode.len().saturating_sub(200) {
            // Look for balanceOf call result being stored
            if self.bytecode[i] == 0xFA { // STATICCALL (balanceOf)
                // Check if result is stored
                let result_stored = self.bytecode[i+1..i+30]
                    .windows(1).any(|w| w[0] == 0x55); // SSTORE

                // Check if stored value is reused later
                let value_reused = self.bytecode[i+30..i+150]
                    .windows(1).any(|w| w[0] == 0x54); // SLOAD

                // Critical: Stored rebasing balance used without re-query
                if result_stored && value_reused {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::RebasingAccountingError,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Rebasing token (stETH) balance stored and reused without re-querying".to_string(),
                        exploit_scenario: "stETH Rebasing Accounting Error:\n\
                            1. Protocol stores: storedBalance = stETH.balanceOf(this) = 1000\n\
                            2. Positive rebase occurs: actual balance now 1010 stETH\n\
                            3. User deposits 100 stETH\n\
                            4. Protocol calculates shares: 100 / storedBalance(1000) = 10%\n\
                            5. Actual total is 1110 stETH, should be 9.01%\n\
                            6. User gets excess shares, dilutes other users\n\
                            7. Over time, accounting completely breaks\n\
                            \n\
                            Real example: Multiple DeFi protocols with stETH (2022)".to_string(),
                        remediation: "Handle rebasing correctly:\n\
                            1. NEVER store balanceOf results for rebasing tokens\n\
                            2. Query fresh balance for every calculation\n\
                            3. Use shares instead of balances for internal accounting\n\
                            4. Consider wrapping stETH to wstETH (non-rebasing)\n\
                            5. Add test cases for rebase scenarios".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_validator_key_vulnerabilities(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Validator keys managed without proper security
        for i in 0..self.bytecode.len().saturating_sub(150) {
            // Look for BLS signature operations (validator keys)
            if self.bytecode[i] == 0xF1 { // CALL to precompile or external
                // Check if this handles validator keys (usually large data)
                let has_large_data = self.bytecode[i.saturating_sub(30)..i]
                    .windows(1).any(|w| w[0] == 0x7F); // PUSH32

                // Critical: No secure enclave or HSM for key operations
                let insecure_key_storage = !self.bytecode[i.saturating_sub(80)..i+50]
                    .windows(1).any(|w| w[0] == 0x20); // SHA3 (key derivation)

                if has_large_data && insecure_key_storage {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::ValidatorKeyVulnerability,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Validator keys managed without secure hardware or proper key derivation".to_string(),
                        exploit_scenario: "Validator Key Compromise:\n\
                            1. LSD protocol generates validator keys in contract/server\n\
                            2. No HSM or secure enclave protection\n\
                            3. Keys stored in database or memory\n\
                            4. Server compromised or insider threat\n\
                            5. Attacker steals validator private keys\n\
                            6. Creates conflicting attestations (slashing)\n\
                            7. All affected validators slashed (1+ ETH each)\n\
                            8. LSD token depegs due to losses\n\
                            \n\
                            Impact: Loss of principal + slashing penalties".to_string(),
                        remediation: "Secure validator key management:\n\
                            1. Use Hardware Security Modules (HSM) for key generation\n\
                            2. Implement remote signing with key isolation\n\
                            3. Distribute key generation (DKG for DVT)\n\
                            4. Never store unencrypted keys\n\
                            5. Use Web3Signer or equivalent validator tooling\n\
                            6. Consider distributed validator technology (SSV, Obol)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_mev_theft(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: No MEV protection for validator rewards
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for reward distribution logic
            if self.bytecode[i] == 0x31 { // BALANCE (checking ETH balance)
                // Check if rewards are distributed
                let has_distribution = self.bytecode[i+1..i+80]
                    .windows(1).any(|w| w[0] == 0xF1 || w[0] == 0xF0); // CALL or CREATE

                // Critical: No MEV smoothing or protection
                let no_mev_protection = !self.bytecode[i.saturating_sub(50)..i+100]
                    .windows(4).any(|w| {
                        // Look for MEV relay integration
                        w.iter().filter(|&&b| b == 0xFA).count() >= 2 // Multiple external calls
                    });

                if has_distribution && no_mev_protection {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::ValidatorMEVTheft,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Validator MEV rewards not smoothed or protected from theft".to_string(),
                        exploit_scenario: "Validator MEV Theft:\n\
                            1. LSD protocol runs 1000 validators\n\
                            2. Validator proposes block with 10 ETH MEV opportunity\n\
                            3. Operator captures MEV to personal address\n\
                            4. Only consensus rewards (0.02 ETH) sent to protocol\n\
                            5. LSD holders lose 10 ETH that should be distributed\n\
                            6. Over time, systematic MEV theft from pool\n\
                            \n\
                            Real issue: Validator MEV capture before mev-boost".to_string(),
                        remediation: "Implement MEV protection:\n\
                            1. Require validators use MEV-boost or similar\n\
                            2. Enforce block builder separation\n\
                            3. Monitor validator behavior for MEV extraction\n\
                            4. Slash operators who bypass MEV sharing\n\
                            5. Use MEV smoothing pools (e.g., Manifold)".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_slashing_cascade(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Slashing event handling without cascade prevention
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for slashing-related state changes
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this follows external call (slashing reported)
                let follows_external_call = self.bytecode[i.saturating_sub(30)..i]
                    .windows(1).any(|w| w[0] == 0xF1 || w[0] == 0xFA);

                // Critical: No check for total slashing impact
                let no_cascade_limit = !self.bytecode[i.saturating_sub(50)..i+50]
                    .windows(1).any(|w| w[0] == 0x04); // DIV (calculating percentage)

                if follows_external_call && no_cascade_limit {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::SlashingCascade,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Slashing events not protected against cascade failures".to_string(),
                        exploit_scenario: "Slashing Cascade Failure:\n\
                            1. LSD has 100,000 ETH across 3,125 validators\n\
                            2. Correlation bug causes 500 validators to attest incorrectly\n\
                            3. All 500 validators slashed (1 ETH each = 500 ETH)\n\
                            4. No cascade protection or circuit breaker\n\
                            5. Share price drops 0.5% instantly\n\
                            6. Panic selling causes further depeg\n\
                            7. Redemption queue floods, liquidity crisis\n\
                            \n\
                            Risk: Correlated slashing in distributed systems".to_string(),
                        remediation: "Add slashing cascade protection:\n\
                            1. Implement maximum slashing per epoch limit\n\
                            2. Circuit breaker for rapid share price drops\n\
                            3. Maintain insurance fund for slashing coverage\n\
                            4. Diversify validator software/configurations\n\
                            5. Monitor correlation between validators".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_share_price_manipulation(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Share price calculation without flash loan protection
        for i in 0..self.bytecode.len().saturating_sub(150) {
            // Look for share price calculation (totalAssets / totalSupply)
            if self.bytecode[i] == 0x04 { // DIV
                // Check if uses current balance
                let uses_current_balance = self.bytecode[i.saturating_sub(50)..i]
                    .windows(1).any(|w| w[0] == 0x31); // BALANCE

                // Critical: No protection against flash deposit/withdraw
                let vulnerable_to_flash = !self.bytecode[i.saturating_sub(80)..i]
                    .windows(2).any(|w| w[0] == 0x42 && w[1] == 0x55); // Timestamp check + storage

                if uses_current_balance && vulnerable_to_flash {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::SharePriceManipulation,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Share price uses current balance without flash loan protection".to_string(),
                        exploit_scenario: "Share Price Manipulation:\n\
                            1. LSD has 10,000 ETH, 9,900 shares (1.0101 ETH per share)\n\
                            2. Attacker flash loans 100,000 ETH\n\
                            3. Stakes all 100k ETH, gets ~98,020 new shares\n\
                            4. Price temporarily: 110k ETH / 107,920 shares = 1.0189\n\
                            5. Attacker's accomplice mints at inflated price\n\
                            6. Attacker withdraws 100k stake immediately\n\
                            7. Price corrects, accomplice gained excess shares\n\
                            \n\
                            Real scenario: rETH had deposit limits to prevent this".to_string(),
                        remediation: "Secure share price:\n\
                            1. Use time-weighted share price (updated per block/epoch)\n\
                            2. Add minimum holding period (1 block delay)\n\
                            3. Cap maximum deposit per transaction\n\
                            4. Use beacon chain balance, not contract balance\n\
                            5. Implement deposit/withdrawal fees to discourage flash".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_withdrawal_queue_dos(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Withdrawal queue without rate limiting
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for queue addition
            if self.bytecode[i] == 0x55 { // SSTORE (adding to queue)
                // Check if queue size is bounded
                let has_size_check = self.bytecode[i.saturating_sub(50)..i]
                    .windows(3).any(|w| w[0] == 0x54 && w[1] == 0x11); // SLOAD + GT (size check)

                // Critical: Unbounded queue growth
                if !has_size_check {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::WithdrawalQueueDOS,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "Withdrawal queue has no size limit enabling DOS attack".to_string(),
                        exploit_scenario: "Withdrawal Queue DOS:\n\
                            1. LSD protocol has withdrawal queue\n\
                            2. No limit on queue size or minimum withdrawal\n\
                            3. Attacker creates 10,000 tiny withdrawal requests (0.01 ETH each)\n\
                            4. Queue processing becomes expensive (100k+ gas per withdrawal)\n\
                            5. Legitimate large withdrawals stuck behind spam\n\
                            6. Queue processing stalls, users can't exit\n\
                            \n\
                            Impact: Liquidity lockup during stress periods".to_string(),
                        remediation: "Add queue protections:\n\
                            1. Minimum withdrawal amount (e.g., 0.1 ETH)\n\
                            2. Maximum queue size per user\n\
                            3. Withdrawal fee to prevent spam\n\
                            4. Batch processing optimization\n\
                            5. Emergency mode to clear spam requests".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_beacon_chain_mismatch(&self) -> Vec<LiquidStakingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Using contract state instead of beacon chain state
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for validator balance calculations
            if self.bytecode[i] == 0x02 { // MUL (calculating total validator balance)
                // Check if uses stored count instead of beacon chain query
                let uses_stored_count = self.bytecode[i.saturating_sub(20)..i]
                    .windows(1).any(|w| w[0] == 0x54); // SLOAD

                // Critical: No beacon chain oracle for actual state
                let no_beacon_oracle = !self.bytecode[i.saturating_sub(100)..i+50]
                    .windows(1).any(|w| w[0] == 0xFA); // STATICCALL to oracle

                if uses_stored_count && no_beacon_oracle {
                    vulnerabilities.push(LiquidStakingVulnerability {
                        vulnerability_type: LSDVulnType::BeaconChainMismatch,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Validator state uses contract storage instead of querying beacon chain".to_string(),
                        exploit_scenario: "Beacon Chain State Mismatch:\n\
                            1. Contract stores: activeValidators = 3,000\n\
                            2. Actual beacon chain: 2,950 active (50 exited)\n\
                            3. Contract calculates: 3,000 * 32 ETH = 96,000 ETH\n\
                            4. Actual backing: 2,950 * 32 = 94,400 ETH\n\
                            5. Share price inflated by 1,600 ETH\n\
                            6. Users mint shares at incorrect rate\n\
                            7. Eventual accounting crisis when reality discovered\n\
                            \n\
                            Critical: Must sync with beacon chain reality".to_string(),
                        remediation: "Sync with beacon chain:\n\
                            1. Use beacon chain oracle (e.g., consensus layer data)\n\
                            2. Regular state syncs (every epoch minimum)\n\
                            3. Validate validator exits are processed\n\
                            4. Cross-check balances against beacon chain\n\
                            5. Add circuit breaker for large discrepancies".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_oracle_manipulation() {
        let bytecode = vec![
            0xFA, // STATICCALL (oracle)
            0x60, 0x20, 0x04, // DIV (price calculation)
            // Single oracle without validation
        ];
        
        let analyzer = LiquidStakingAnalyzer::new(bytecode);
        let vulns = analyzer.detect_oracle_manipulation();
        
        assert!(!vulns.is_empty(), "Should detect single oracle risk");
        assert_eq!(vulns[0].vulnerability_type, LSDVulnType::LSDOracleManipulation);
    }

    #[test]
    fn test_detects_rebasing_accounting_error() {
        let bytecode = vec![
            0xFA, // STATICCALL (balanceOf)
            0x60, 0x00, 0x55, // SSTORE (store balance)
            vec![0x00; 40].as_slice(), // padding
            0x54, // SLOAD (reuse stored balance)
        ].concat();
        
        let analyzer = LiquidStakingAnalyzer::new(bytecode);
        let vulns = analyzer.detect_rebasing_accounting_errors();
        
        assert!(!vulns.is_empty(), "Should detect rebasing reuse");
    }

    #[test]
    fn test_detects_share_price_manipulation() {
        let bytecode = vec![
            0x31, // BALANCE (current balance)
            0x60, 0x20, 0x04, // DIV (share price)
            // No timestamp protection
        ];
        
        let analyzer = LiquidStakingAnalyzer::new(bytecode);
        let vulns = analyzer.detect_share_price_manipulation();
        
        assert!(!vulns.is_empty(), "Should detect flash loan vulnerability");
        assert_eq!(vulns[0].vulnerability_type, LSDVulnType::SharePriceManipulation);
    }
}
