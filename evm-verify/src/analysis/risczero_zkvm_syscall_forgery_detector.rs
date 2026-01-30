use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct RisczeroZkvmSyscallForgeryDetector {
    bytecode: Vec<u8>,
}

impl RisczeroZkvmSyscallForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_syscall_forgery() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "zkVM syscalls can be forged to bypass I/O validation, allowing manipulation of proof inputs/outputs.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_journal_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::High,
                description: "Guest program journal can be manipulated to alter committed outputs without detection.".to_string(),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_syscall_forgery(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(50) {
            if bytecode[i] == 0xFA { // STATICCALL (zkVM syscall interface)
                let mut has_io_check = false;
                let mut has_commit = false;

                for j in i+1..std::cmp::min(i+45, bytecode.len()) {
                    if bytecode[j] == 0x15 { // ISZERO (validation)
                        has_io_check = true;
                    }
                    if bytecode[j] == 0x55 && !has_io_check { // SSTORE without check
                        has_commit = true;
                    }
                }

                if has_commit && !has_io_check {
                    return Some(i);
                }
            }
        }

        None
    }

    fn detect_journal_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0x20 { // SHA3 (journal hash)
                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x52 { // MSTORE (modify journal)
                        for k in j+1..std::cmp::min(j+15, bytecode.len()) {
                            if bytecode[k] == 0x20 { // SHA3 (rehash)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}
