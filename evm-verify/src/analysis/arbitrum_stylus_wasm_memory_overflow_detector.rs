use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ArbitrumStylusWasmMemoryOverflowDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumStylusWasmMemoryOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_wasm_memory_overflow() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "WASM linear memory can overflow due to unbounded growth or manipulation causing contract DOS or state corruption.".to_string(),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_memory_allocation_dos() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Excessive memory allocations can DOS Stylus contracts through resource exhaustion.".to_string(),
                pc,
                confidence: 0.83,
            });
        }

        findings
    }

    fn detect_wasm_memory_overflow(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0x52 { // MSTORE (memory write)
                let mut has_size_calc = false;
                let mut lacks_bound_check = true;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x01 { // ADD (size calculation)
                        has_size_calc = true;
                    }
                    if bytecode[j] == 0x10 || bytecode[j] == 0x11 { // LT/GT (bounds check)
                        lacks_bound_check = false;
                    }
                }

                if has_size_calc && lacks_bound_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_memory_allocation_dos(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x37 { // CALLDATACOPY (user input)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x52 { // MSTORE (allocate)
                        let mut has_size_limit = false;
                        for k in i..j {
                            if bytecode[k] == 0x10 || bytecode[k] == 0x11 { // LT/GT
                                has_size_limit = true;
                                break;
                            }
                        }
                        if !has_size_limit {
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }
}
