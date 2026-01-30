use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct ArbitrumStylusHostIoSyscallAbuseDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumStylusHostIoSyscallAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_host_io_syscall_abuse() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Host I/O syscalls can be abused to bypass gas metering or access unauthorized state.".to_string(),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_storage_syscall_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Medium,
                description: "Storage syscalls can be manipulated to access storage slots outside contract bounds.".to_string(),
                pc,
                confidence: 0.81,
            });
        }

        findings
    }

    fn detect_host_io_syscall_abuse(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (host I/O)
                let mut has_gas_check = false;
                let mut has_repeated_calls = false;
                let mut call_count = 0;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x5A { // GAS (check gas)
                        has_gas_check = true;
                    }
                    if bytecode[j] == 0xFA { // STATICCALL (repeated)
                        call_count += 1;
                        if call_count >= 2 {
                            has_repeated_calls = true;
                        }
                    }
                }

                if has_repeated_calls && !has_gas_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_storage_syscall_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x54 { // SLOAD (storage access)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x01 || bytecode[j] == 0x02 { // ADD/MUL (slot calculation)
                        let mut has_bound_check = false;
                        for k in i..j {
                            if bytecode[k] == 0x16 { // AND (mask/bound)
                                has_bound_check = true;
                                break;
                            }
                        }
                        if !has_bound_check {
                            return Some(i);
                        }
                    }
                }
            }
        }

        None
    }
}
