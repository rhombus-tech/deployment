use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrownieFixtureVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BrowniePytestFixtureStatePollutionDetector {
    bytecode: Vec<u8>,
}

impl BrowniePytestFixtureStatePollutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BrownieFixtureVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_shared_state_pollution());
        vulnerabilities.extend(self.detect_account_balance_interference());
        vulnerabilities.extend(self.detect_global_variable_leak());
        vulnerabilities
    }

    fn detect_shared_state_pollution(&self) -> Vec<BrownieFixtureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| b == 0x55).count() >= 3 && !window.iter().any(|&b| b == 0xF0) {
                    vulns.push(BrownieFixtureVulnerability {
                        pc, vulnerability_type: "SharedStatePollution".to_string(),
                        description: format!("Storage writes at PC {} persist across tests if fixture scope not function-level.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_account_balance_interference(&self) -> Vec<BrownieFixtureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (balance transfer)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().any(|&b| b == 0x47) && !window.iter().any(|&b| b == 0x33) {
                    vulns.push(BrownieFixtureVulnerability {
                        pc, vulnerability_type: "AccountBalanceInterference".to_string(),
                        description: format!("Balance transfer at PC {} affects test account balances across tests without reset.", pc),
                        confidence: 0.76,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_global_variable_leak(&self) -> Vec<BrownieFixtureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().filter(|&&b| b == 0x54).count() >= 2 {
                    vulns.push(BrownieFixtureVulnerability {
                        pc, vulnerability_type: "GlobalVariableLeak".to_string(),
                        description: format!("Storage reads at PC {} depend on global state modified by previous tests.", pc),
                        confidence: 0.74,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
