// EVM Opcodes
//
// This module provides constants for EVM opcodes used in bytecode analysis.

/// STOP opcode
pub const STOP: u8 = 0x00;

/// ADD opcode
pub const ADD: u8 = 0x01;

/// MUL opcode
pub const MUL: u8 = 0x02;

/// SUB opcode
pub const SUB: u8 = 0x03;

/// DIV opcode
pub const DIV: u8 = 0x04;

/// SDIV opcode
pub const SDIV: u8 = 0x05;

/// MOD opcode
pub const MOD: u8 = 0x06;

/// SMOD opcode
pub const SMOD: u8 = 0x07;

/// ADDMOD opcode
pub const ADDMOD: u8 = 0x08;

/// MULMOD opcode
pub const MULMOD: u8 = 0x09;

/// EXP opcode
pub const EXP: u8 = 0x0A;

/// SIGNEXTEND opcode
pub const SIGNEXTEND: u8 = 0x0B;

/// LT opcode
pub const LT: u8 = 0x10;

/// GT opcode
pub const GT: u8 = 0x11;

/// SLT opcode
pub const SLT: u8 = 0x12;

/// SGT opcode
pub const SGT: u8 = 0x13;

/// EQ opcode
pub const EQ: u8 = 0x14;

/// ISZERO opcode
pub const ISZERO: u8 = 0x15;

/// AND opcode
pub const AND: u8 = 0x16;

/// OR opcode
pub const OR: u8 = 0x17;

/// XOR opcode
pub const XOR: u8 = 0x18;

/// NOT opcode
pub const NOT: u8 = 0x19;

/// BYTE opcode
pub const BYTE: u8 = 0x1A;

/// SHL opcode
pub const SHL: u8 = 0x1B;

/// SHR opcode
pub const SHR: u8 = 0x1C;

/// SAR opcode
pub const SAR: u8 = 0x1D;

/// SHA3 opcode
pub const SHA3: u8 = 0x20;

/// ADDRESS opcode
pub const ADDRESS: u8 = 0x30;

/// BALANCE opcode
pub const BALANCE: u8 = 0x31;

/// ORIGIN opcode
pub const ORIGIN: u8 = 0x32;

/// CALLER opcode
pub const CALLER: u8 = 0x33;

/// CALLVALUE opcode
pub const CALLVALUE: u8 = 0x34;

/// CALLDATALOAD opcode
pub const CALLDATALOAD: u8 = 0x35;

/// CALLDATASIZE opcode
pub const CALLDATASIZE: u8 = 0x36;

/// CALLDATACOPY opcode
pub const CALLDATACOPY: u8 = 0x37;

/// CODESIZE opcode
pub const CODESIZE: u8 = 0x38;

/// CODECOPY opcode
pub const CODECOPY: u8 = 0x39;

/// GASPRICE opcode
pub const GASPRICE: u8 = 0x3A;

/// EXTCODESIZE opcode
pub const EXTCODESIZE: u8 = 0x3B;

/// EXTCODECOPY opcode
pub const EXTCODECOPY: u8 = 0x3C;

/// RETURNDATASIZE opcode
pub const RETURNDATASIZE: u8 = 0x3D;

/// RETURNDATACOPY opcode
pub const RETURNDATACOPY: u8 = 0x3E;

/// EXTCODEHASH opcode
pub const EXTCODEHASH: u8 = 0x3F;

/// BLOCKHASH opcode
pub const BLOCKHASH: u8 = 0x40;

/// COINBASE opcode
pub const COINBASE: u8 = 0x41;

/// TIMESTAMP opcode
pub const TIMESTAMP: u8 = 0x42;

/// NUMBER opcode
pub const NUMBER: u8 = 0x43;

/// DIFFICULTY opcode
pub const DIFFICULTY: u8 = 0x44;

/// GASLIMIT opcode
pub const GASLIMIT: u8 = 0x45;

/// CHAINID opcode
pub const CHAINID: u8 = 0x46;

/// SELFBALANCE opcode
pub const SELFBALANCE: u8 = 0x47;

/// BASEFEE opcode
pub const BASEFEE: u8 = 0x48;

/// POP opcode
pub const POP: u8 = 0x50;

/// MLOAD opcode
pub const MLOAD: u8 = 0x51;

/// MSTORE opcode
pub const MSTORE: u8 = 0x52;

/// MSTORE8 opcode
pub const MSTORE8: u8 = 0x53;

/// SLOAD opcode
pub const SLOAD: u8 = 0x54;

/// SSTORE opcode
pub const SSTORE: u8 = 0x55;

/// JUMP opcode
pub const JUMP: u8 = 0x56;

/// JUMPI opcode
pub const JUMPI: u8 = 0x57;

/// PC opcode
pub const PC: u8 = 0x58;

/// MSIZE opcode
pub const MSIZE: u8 = 0x59;

/// GAS opcode
pub const GAS: u8 = 0x5A;

/// JUMPDEST opcode
pub const JUMPDEST: u8 = 0x5B;

/// PUSH1 opcode
pub const PUSH1: u8 = 0x60;

/// LOG0 opcode
pub const LOG0: u8 = 0xA0;

/// LOG1 opcode
pub const LOG1: u8 = 0xA1;

/// LOG2 opcode
pub const LOG2: u8 = 0xA2;

/// LOG3 opcode
pub const LOG3: u8 = 0xA3;

/// LOG4 opcode
pub const LOG4: u8 = 0xA4;

/// CREATE opcode
pub const CREATE: u8 = 0xF0;

/// CALL opcode
pub const CALL: u8 = 0xF1;

/// CALLCODE opcode
pub const CALLCODE: u8 = 0xF2;

/// RETURN opcode
pub const RETURN: u8 = 0xF3;

/// DELEGATECALL opcode
pub const DELEGATECALL: u8 = 0xF4;

/// CREATE2 opcode
pub const CREATE2: u8 = 0xF5;

/// STATICCALL opcode
pub const STATICCALL: u8 = 0xFA;

/// REVERT opcode
pub const REVERT: u8 = 0xFD;

/// INVALID opcode
pub const INVALID: u8 = 0xFE;

/// SELFDESTRUCT opcode
pub const SELFDESTRUCT: u8 = 0xFF;

/// Opcode trait for working with opcodes
pub trait Opcode {
    /// Get the name of an opcode
    fn name(opcode: u8) -> &'static str;
    
    /// Get the gas cost of an opcode
    fn gas_cost(opcode: u8) -> u64;
    
    /// Check if an opcode is a PUSH opcode
    fn is_push(opcode: u8) -> bool;
    
    /// Get the size of a PUSH opcode's immediate value
    fn push_size(opcode: u8) -> Option<usize>;
}

/// Opcode implementation
impl Opcode for u8 {
    /// Get the name of an opcode
    fn name(opcode: u8) -> &'static str {
        match opcode {
            STOP => "STOP",
            ADD => "ADD",
            MUL => "MUL",
            SUB => "SUB",
            DIV => "DIV",
            SDIV => "SDIV",
            MOD => "MOD",
            SMOD => "SMOD",
            ADDMOD => "ADDMOD",
            MULMOD => "MULMOD",
            EXP => "EXP",
            SIGNEXTEND => "SIGNEXTEND",
            LT => "LT",
            GT => "GT",
            SLT => "SLT",
            SGT => "SGT",
            EQ => "EQ",
            ISZERO => "ISZERO",
            AND => "AND",
            OR => "OR",
            XOR => "XOR",
            NOT => "NOT",
            BYTE => "BYTE",
            SHL => "SHL",
            SHR => "SHR",
            SAR => "SAR",
            SHA3 => "SHA3",
            ADDRESS => "ADDRESS",
            BALANCE => "BALANCE",
            ORIGIN => "ORIGIN",
            CALLER => "CALLER",
            CALLVALUE => "CALLVALUE",
            CALLDATALOAD => "CALLDATALOAD",
            CALLDATASIZE => "CALLDATASIZE",
            CALLDATACOPY => "CALLDATACOPY",
            CODESIZE => "CODESIZE",
            CODECOPY => "CODECOPY",
            GASPRICE => "GASPRICE",
            EXTCODESIZE => "EXTCODESIZE",
            EXTCODECOPY => "EXTCODECOPY",
            RETURNDATASIZE => "RETURNDATASIZE",
            RETURNDATACOPY => "RETURNDATACOPY",
            EXTCODEHASH => "EXTCODEHASH",
            BLOCKHASH => "BLOCKHASH",
            COINBASE => "COINBASE",
            TIMESTAMP => "TIMESTAMP",
            NUMBER => "NUMBER",
            DIFFICULTY => "DIFFICULTY",
            GASLIMIT => "GASLIMIT",
            CHAINID => "CHAINID",
            SELFBALANCE => "SELFBALANCE",
            BASEFEE => "BASEFEE",
            POP => "POP",
            MLOAD => "MLOAD",
            MSTORE => "MSTORE",
            MSTORE8 => "MSTORE8",
            SLOAD => "SLOAD",
            SSTORE => "SSTORE",
            JUMP => "JUMP",
            JUMPI => "JUMPI",
            PC => "PC",
            MSIZE => "MSIZE",
            GAS => "GAS",
            JUMPDEST => "JUMPDEST",
            LOG0 => "LOG0",
            LOG1 => "LOG1",
            LOG2 => "LOG2",
            LOG3 => "LOG3",
            LOG4 => "LOG4",
            CREATE => "CREATE",
            CALL => "CALL",
            CALLCODE => "CALLCODE",
            RETURN => "RETURN",
            DELEGATECALL => "DELEGATECALL",
            CREATE2 => "CREATE2",
            STATICCALL => "STATICCALL",
            REVERT => "REVERT",
            INVALID => "INVALID",
            SELFDESTRUCT => "SELFDESTRUCT",
            _ => {
                if Self::is_push(opcode) {
                    "PUSH"
                } else {
                    "UNKNOWN"
                }
            }
        }
    }
    
    /// Get the gas cost of an opcode
    fn gas_cost(opcode: u8) -> u64 {
        match opcode {
            STOP => 0,
            ADD | MUL | SUB | DIV | SDIV | MOD | SMOD | NOT | LT | GT | SLT | SGT | EQ | ISZERO | AND | OR | XOR | BYTE => 3,
            ADDMOD | MULMOD => 8,
            EXP => 10, // Base cost, actual cost depends on exponent
            SHA3 => 30, // Base cost, actual cost depends on size
            ADDRESS | ORIGIN | CALLER | CALLVALUE | CALLDATASIZE | CODESIZE | GASPRICE | COINBASE | TIMESTAMP | NUMBER | DIFFICULTY | GASLIMIT | RETURNDATASIZE | CHAINID | SELFBALANCE | BASEFEE => 2,
            BALANCE | EXTCODESIZE | EXTCODEHASH => 700,
            CALLDATALOAD | MLOAD | MSTORE | MSTORE8 | SLOAD => 3,
            SSTORE => 20000, // For new value, 5000 for update
            JUMP | JUMPI => 10,
            PC | MSIZE | GAS => 2,
            JUMPDEST => 1,
            PUSH1 => 3,
            LOG0 => 375,
            LOG1 => 750,
            LOG2 => 1125,
            LOG3 => 1500,
            LOG4 => 1875,
            CREATE | CREATE2 => 32000,
            CALL | CALLCODE => 700, // Base cost
            DELEGATECALL | STATICCALL => 700, // Base cost
            RETURN | REVERT => 0,
            SELFDESTRUCT => 5000,
            _ => 3, // Default cost
        }
    }
    
    /// Check if an opcode is a PUSH opcode
    fn is_push(opcode: u8) -> bool {
        opcode >= PUSH1 && opcode <= 0x7F
    }
    
    /// Get the size of a PUSH opcode's immediate value
    fn push_size(opcode: u8) -> Option<usize> {
        if Self::is_push(opcode) {
            Some((opcode - PUSH1 + 1) as usize)
        } else {
            None
        }
    }
}
