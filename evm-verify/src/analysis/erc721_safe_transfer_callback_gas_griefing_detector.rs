use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc721SafeTransferGasGriefingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Erc721SafeTransferCallbackGasGriefingDetector {
    bytecode: Vec<u8>,
}

impl Erc721SafeTransferCallbackGasGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Erc721SafeTransferGasGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unlimited_gas_callback());
        vulnerabilities.extend(self.detect_revert_gas_bomb());
        vulnerabilities.extend(self.detect_return_data_bomb());
        vulnerabilities
    }

    fn detect_unlimited_gas_callback(&self) -> Vec<Erc721SafeTransferGasGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (onERC721Received callback)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let prepares_callback = self.bytecode[start..pc].iter().filter(|&&b| b == 0x60).count() >= 4;
                if prepares_callback {
                    let limits_gas = self.bytecode[start..pc].iter().filter(|&&b| b == 0x5A).count() >= 1;
                    if !limits_gas {
                        vulns.push(Erc721SafeTransferGasGriefingVulnerability {
                            pc, vulnerability_type: "UnlimitedGasCallback".to_string(),
                            description: format!("ERC-721 safeTransferFrom callback at PC {} forwards all remaining gas to receiver, enabling griefing. Attack: malicious receiver's onERC721Received() consumes excessive gas, making NFT transfers prohibitively expensive. Real attack: attacker creates contract with onERC721Received that executes expensive loop, marketplace calls safeTransferFrom, transaction costs 30M gas, DoS. Example: OpenSea transferring NFT to griefer contract, callback runs SHA256 in loop consuming all 30M gas limit, transfer fails or costs $1000+. Missing: gas limit on callback, typically gasleft()/64 or fixed amount like 50000. Should implement: call{{gas: 50000}}(abi.encodeWithSelector(IERC721Receiver.onERC721Received.selector, ...)). Fix: limit callback gas to prevent griefing attacks.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_revert_gas_bomb(&self) -> Vec<Erc721SafeTransferGasGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x3D { // RETURNDATASIZE (checking callback return)
                let window_end = (pc + 60).min(self.bytecode.len());
                let copies_returndata = self.bytecode[pc..window_end].iter().any(|&b| b == 0x3E);
                if copies_returndata {
                    let checks_size = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !checks_size {
                        vulns.push(Erc721SafeTransferGasGriefingVulnerability {
                            pc, vulnerability_type: "RevertGasBomb".to_string(),
                            description: format!("Return data copy at PC {} doesn't check size before copying, vulnerable to revert data bomb. Attack: malicious onERC721Received reverts with massive return data (>1MB), RETURNDATACOPY tries copying huge data, OOG. Real attack: griefer contract reverts with 1MB of data, safeTransferFrom calls RETURNDATACOPY, copies 1MB consuming excessive gas, transaction fails. Example: receiver.onERC721Received() reverts with return abi.encode(new bytes(1000000)), contract does RETURNDATACOPY without checking RETURNDATASIZE, costs millions of gas. Missing: check returndatasize() before copy, limit to reasonable size like 256 bytes. Fix: if returndatasize() > 256 revert, or only copy first 256 bytes to check function selector.", pc),
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

    fn detect_return_data_bomb(&self) -> Vec<Erc721SafeTransferGasGriefingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x3E { // RETURNDATACOPY
                let start = if pc > 80 { pc - 80 } else { 0 };
                let has_size_validation = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                if !has_size_validation {
                    vulns.push(Erc721SafeTransferGasGriefingVulnerability {
                        pc, vulnerability_type: "ReturnDataBomb".to_string(),
                        description: format!("RETURNDATACOPY at PC {} copies unbounded return data from onERC721Received, enabling memory expansion attack. Attack: callback returns gigantic data, contract copies all to memory, memory expansion cost quadratic, OOG griefing. Real vulnerability: onERC721Received() returns bytes array with length=type(uint256).max, RETURNDATACOPY attempts allocation, memory expansion costs become astronomical. Example: malicious receiver returns 2^32 bytes, memory expansion formula: cost = (new_size^2 / 512) - (old_size^2 / 512), copying causes multi-million gas cost. Missing: validate returndatasize() <= 256 before copy, or use fixed-size buffer. Should implement: require(returndatasize() == 32) to only accept 4-byte selector return. Fix: bound return data size or use try/catch with gas limit.", pc),
                        confidence: 0.80,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
