/// Paymaster Subsidy Gaming Detector
/// Detects AA paymaster fund draining vulnerabilities (ERC-4337)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymasterSubsidyVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct PaymasterSubsidyGamingDetector {
    bytecode: Vec<u8>,
}

impl PaymasterSubsidyGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PaymasterSubsidyVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unlimited_gas_sponsorship());
        vulnerabilities.extend(self.detect_no_rate_limiting());
        vulnerabilities.extend(self.detect_subsidy_calculation_bug());
        vulnerabilities
    }

    fn detect_unlimited_gas_sponsorship(&self) -> Vec<PaymasterSubsidyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_paymaster_validation(pc) {
                if !self.has_gas_limit_check(pc, 180) {
                    vulnerabilities.push(PaymasterSubsidyVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Paymaster at PC {} doesn't limit gas sponsorship. \
                            Attackers can drain paymaster by submitting high-gas operations.",
                            pc
                        ),
                        exploit_scenario:
                            "Unlimited Gas Drain:\n\
                             1. Paymaster offers free gas for all users\n\
                             2. Attacker creates UserOps with maxGasLimit\n\
                             3. Attacker's operations use maximum allowed gas\n\
                             4. Paymaster pays for all gas\n\
                             5. Attacker repeats with many accounts\n\
                             6. Paymaster funds drained within hours\n\n\
                             Fix:\n\
                             uint256 constant MAX_GAS_SPONSORED = 1_000_000;\n\
                             mapping(address => uint256) public dailyGasUsed;\n\
                             mapping(address => uint256) public lastResetTime;\n\
                             \n\
                             function validatePaymasterUserOp(\n\
                                 UserOperation calldata userOp,\n\
                                 bytes32 userOpHash,\n\
                                 uint256 maxCost\n\
                             ) external returns (bytes memory context, uint256 validationData) {\n\
                                 require(userOp.callGasLimit <= MAX_GAS_SPONSORED, 'Gas too high');\n\
                                 \n\
                                 if (block.timestamp > lastResetTime[userOp.sender] + 1 days) {\n\
                                     dailyGasUsed[userOp.sender] = 0;\n\
                                     lastResetTime[userOp.sender] = block.timestamp;\n\
                                 }\n\
                                 \n\
                                 require(\n\
                                     dailyGasUsed[userOp.sender] + userOp.callGasLimit <= 5_000_000,\n\
                                     'Daily limit exceeded'\n\
                                 );\n\
                                 \n\
                                 dailyGasUsed[userOp.sender] += userOp.callGasLimit;\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_no_rate_limiting(&self) -> Vec<PaymasterSubsidyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_paymaster_validation(pc) {
                if !self.has_rate_limit_storage(pc, 200) {
                    vulnerabilities.push(PaymasterSubsidyVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Paymaster at PC {} has no rate limiting. \
                            Attackers can spam operations to exhaust funds quickly.",
                            pc
                        ),
                        exploit_scenario:
                            "Paymaster Spam Attack:\n\
                             1. Paymaster sponsors first 100 operations for any user\n\
                             2. Attacker creates 1000 accounts (Sybil)\n\
                             3. Each account submits 100 operations\n\
                             4. Total: 100,000 sponsored operations\n\
                             5. Paymaster pays for all of them\n\
                             6. Legitimate users can't use paymaster (funds exhausted)\n\n\
                             Fix:\n\
                             struct UserData {\n\
                                 uint128 opsCount;\n\
                                 uint128 lastOpTime;\n\
                             }\n\
                             mapping(address => UserData) public userData;\n\
                             \n\
                             uint256 constant MAX_OPS_PER_HOUR = 10;\n\
                             uint256 constant COOLDOWN = 1 hours;\n\
                             \n\
                             function validatePaymasterUserOp(...) external {\n\
                                 UserData storage data = userData[userOp.sender];\n\
                                 \n\
                                 if (block.timestamp >= data.lastOpTime + COOLDOWN) {\n\
                                     data.opsCount = 0;\n\
                                 }\n\
                                 \n\
                                 require(data.opsCount < MAX_OPS_PER_HOUR, 'Rate limit');\n\
                                 data.opsCount++;\n\
                                 data.lastOpTime = uint128(block.timestamp);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_subsidy_calculation_bug(&self) -> Vec<PaymasterSubsidyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(180) {
            if self.is_paymaster_validation(pc) {
                if self.has_arithmetic_without_checks(pc, 150) {
                    vulnerabilities.push(PaymasterSubsidyVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.70,
                        description: format!(
                            "Paymaster subsidy calculation at PC {} lacks bounds checking. \
                            Integer overflow/underflow can cause incorrect sponsorship amounts.",
                            pc
                        ),
                        exploit_scenario:
                            "Subsidy Calculation Overflow:\n\
                             1. Paymaster calculates: subsidy = baseGas * gasPrice * multiplier\n\
                             2. Attacker sets very high gasPrice\n\
                             3. Multiplication overflows\n\
                             4. subsidy wraps to small value\n\
                             5. Paymaster thinks it's sponsoring $0.01\n\
                             6. Actually sponsors $10,000 worth of gas\n\
                             7. Attacker repeats to drain funds\n\n\
                             Fix:\n\
                             function validatePaymasterUserOp(...) external {\n\
                                 uint256 maxGasCost = userOp.callGasLimit + userOp.verificationGasLimit + \n\
                                     userOp.preVerificationGas;\n\
                                 \n\
                                 uint256 maxFeePerGas = userOp.maxFeePerGas;\n\
                                 require(maxFeePerGas <= 1000 gwei, 'Gas price too high');\n\
                                 \n\
                                 uint256 maxCost;\n\
                                 bool overflow;\n\
                                 unchecked {\n\
                                     maxCost = maxGasCost * maxFeePerGas;\n\
                                     overflow = maxCost / maxGasCost != maxFeePerGas;\n\
                                 }\n\
                                 require(!overflow, 'Cost overflow');\n\
                                 require(maxCost <= MAX_SPONSOR_AMOUNT, 'Cost too high');\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_paymaster_validation(&self, pc: usize) -> bool {
        if pc + 60 >= self.bytecode.len() { return false; }
        // Look for validatePaymasterUserOp selector 0xf465c77e
        self.bytecode[pc..].windows(4).take(60).any(|w| w == [0xf4, 0x65, 0xc7, 0x7e])
    }

    fn has_gas_limit_check(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut has_gas_comparison = false;
        for i in pc..end {
            if matches!(self.bytecode[i], 0x10 | 0x11) { // LT or GT
                for j in (i + 1)..(i + 15).min(end) {
                    if self.bytecode[j] == 0xfd { // REVERT
                        has_gas_comparison = true;
                        break;
                    }
                }
            }
        }
        has_gas_comparison
    }

    fn has_rate_limit_storage(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut sload_count = 0;
        let mut sstore_count = 0;
        for i in pc..end {
            if self.bytecode[i] == 0x54 { sload_count += 1; }
            if self.bytecode[i] == 0x55 { sstore_count += 1; }
        }
        sload_count >= 2 && sstore_count >= 1
    }

    fn has_arithmetic_without_checks(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut has_mul = false;
        let mut has_overflow_check = false;
        for i in pc..end {
            if self.bytecode[i] == 0x02 { has_mul = true; }
            if has_mul && matches!(self.bytecode[i], 0x10 | 0x11) {
                for j in (i + 1)..(i + 10).min(end) {
                    if self.bytecode[j] == 0xfd {
                        has_overflow_check = true;
                        break;
                    }
                }
            }
        }
        has_mul && !has_overflow_check
    }
}
