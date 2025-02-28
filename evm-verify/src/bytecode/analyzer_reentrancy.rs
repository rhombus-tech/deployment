/// Detect reentrancy vulnerabilities in the bytecode
fn detect_reentrancy(&self) -> Result<Vec<SecurityWarning>> {
    let mut warnings = Vec::new();
    let bytecode_vec: Vec<u8> = self.bytecode.iter().copied().collect();
    
    // Track storage reads, calls, and storage writes
    let mut storage_reads = Vec::new();
    let mut external_calls = Vec::new();
    let mut storage_writes = Vec::new();
    
    // Scan for storage reads, external calls, and storage writes
    for i in 0..bytecode_vec.len() {
        match bytecode_vec[i] {
            // SLOAD - Storage read
            0x54 => {
                storage_reads.push(i);
            },
            // CALL, CALLCODE, DELEGATECALL, STATICCALL - External calls
            0xF1 | 0xF2 | 0xF4 | 0xFA => {
                external_calls.push(i);
            },
            // SSTORE - Storage write
            0x55 => {
                storage_writes.push(i);
            },
            _ => {}
        }
    }
    
    // Check for reentrancy pattern: storage read -> external call -> storage write
    for &call_pos in &external_calls {
        // Find storage reads before the call
        let reads_before_call: Vec<_> = storage_reads.iter()
            .filter(|&&pos| pos < call_pos)
            .collect();
        
        // Find storage writes after the call
        let writes_after_call: Vec<_> = storage_writes.iter()
            .filter(|&&pos| pos > call_pos)
            .collect();
        
        // If we have both reads before and writes after, potential reentrancy
        if !reads_before_call.is_empty() && !writes_after_call.is_empty() {
            let warning = SecurityWarning::reentrancy(
                call_pos as u64,
                H256::zero() // Placeholder for the actual storage slot
            );
            warnings.push(warning);
        }
    }
    
    Ok(warnings)
}
