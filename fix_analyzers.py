#!/usr/bin/env python3
import re
import sys

def fix_analyzer_file(filepath):
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Fix imports
    content = content.replace('use crate::bytecode::opcodes::Opcode;', 'use crate::bytecode::opcodes;')
    
    # Fix function signatures
    content = re.sub(r'opcodes: &\[\(usize, Opcode\)\]', 'opcodes: &[(usize, u8)]', content)
    content = re.sub(r'Vec<\(usize, Opcode\)>', 'Vec<(usize, u8)>', content)
    
    # Fix Opcode references - specific patterns first
    content = content.replace('Opcode::PUSH4', '0x63')
    content = content.replace('Opcode::PUSH1', '0x60')
    
    # Fix remaining Opcode:: references to opcodes::
    opcodes_list = ['GAS', 'CALL', 'DELEGATECALL', 'STATICCALL', 'CALLCODE',
                    'SLOAD', 'SSTORE', 'RETURN', 'REVERT', 'STOP',
                    'MOD', 'DIV', 'SDIV', 'TIMESTAMP', 'NUMBER', 'CHAINID',
                    'GT', 'GE', 'LT', 'LE', 'EQ', 'ISZERO',
                    'JUMP', 'JUMPI', 'CALLER', 'SHA3']
    
    for op in opcodes_list:
        content = content.replace(f'Opcode::{op}', f'opcodes::{op}')
    
    # Fix matches! patterns
    # matches!(op, XXX) -> *op == XXX
    content = re.sub(r'matches!\(op, ([^\)]+)\)', r'*op == \1', content)
    content = re.sub(r'matches!\(opcode, ([^\)]+)\)', r'*opcode == \1', content)
    
    # Fix if let patterns  
    # if let Opcode::X = opcode -> if *opcode == X
    content = re.sub(r'if let\s+([^\s]+)\s*=\s*opcode', r'if *opcode == \1', content)
    content = re.sub(r'if let\s+([^\s]+)\s*=\s*op', r'if *op == \1', content)
    
    # Fix parse_opcodes to return Vec<(usize, u8)>
    content = re.sub(
        r'fn parse_opcodes\(&self, bytecode: &\[u8\]\) -> Vec<\(usize, Opcode\)>',
        r'fn parse_opcodes(&self, bytecode: &[u8]) -> Vec<(usize, u8)>',
        content
    )
    
    # Fix Opcode::PUSH(n) pattern in parse_opcodes
    content = re.sub(
        r'let opcode = Opcode::from_u8\(bytecode\[pc\]\);',
        r'let opcode = bytecode[pc];',
        content
    )
    content = re.sub(
        r'if let Opcode::PUSH\(n\) = opcode \{',
        r'if opcode >= 0x60 && opcode <= 0x7f {',
        content
    )
    content = re.sub(
        r'pc \+= n as usize;',
        r'let n = (opcode - 0x60 + 1) as usize;\n                pc += n;',
        content
    )
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"Fixed: {filepath}")

if __name__ == '__main__':
    files = [
        'intent_protocol_exploits.rs',
        'layer2_exploits.rs',
        'hooks_callback_exploits.rs',
        'concentrated_liquidity_exploits.rs',
        'privacy_zk_exploits.rs',
        'mev_protection_exploits.rs',
        'censorship_resistance_exploits.rs'
    ]
    
    for f in files:
        fix_analyzer_file(f'src/analysis/{f}')
