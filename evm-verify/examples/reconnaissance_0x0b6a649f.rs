/// Reconnaissance: Decompile and analyze 0x0b6a649f for SELFDESTRUCT vulnerabilities
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use std::collections::{HashMap, HashSet};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0b6a649f01fc7da4295443342c9f283bb968f3fa")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 RECONNAISSANCE: 0x0b6a649f01fc7da4295443342c9f283bb968f3fa");
    println!("{}", "=".repeat(100));
    println!("Bytecode size: {} bytes", code.len());
    
    // Step 1: Find all SELFDESTRUCT opcodes
    println!("\n{}", "=".repeat(100));
    println!("STEP 1: LOCATE SELFDESTRUCT OPCODES (0xFF)");
    println!("{}", "=".repeat(100));
    
    let mut selfdestruct_locations = Vec::new();
    for (i, &byte) in code.iter().enumerate() {
        if byte == 0xFF {
            selfdestruct_locations.push(i);
        }
    }
    
    println!("\n✓ Found {} SELFDESTRUCT opcodes", selfdestruct_locations.len());
    for (idx, pos) in selfdestruct_locations.iter().take(10).enumerate() {
        println!("  {}. Position: {:#06x}", idx + 1, pos);
    }
    if selfdestruct_locations.len() > 10 {
        println!("  ... and {} more", selfdestruct_locations.len() - 10);
    }
    
    // Step 2: Extract function selectors (first 4 bytes after PUSH4 in function dispatcher)
    println!("\n{}", "=".repeat(100));
    println!("STEP 2: EXTRACT FUNCTION SELECTORS");
    println!("{}", "=".repeat(100));
    
    let mut function_selectors = HashMap::new();
    let mut i = 0;
    while i < code.len() - 4 {
        // Look for PUSH4 (0x63) followed by 4 bytes - common function selector pattern
        if code[i] == 0x63 && i + 4 < code.len() {
            let selector = [code[i+1], code[i+2], code[i+3], code[i+4]];
            let selector_hex = format!("0x{:02x}{:02x}{:02x}{:02x}", 
                selector[0], selector[1], selector[2], selector[3]);
            function_selectors.insert(i, selector_hex);
        }
        i += 1;
    }
    
    println!("\n✓ Found {} potential function selectors:", function_selectors.len());
    let mut sorted_selectors: Vec<_> = function_selectors.iter().collect();
    sorted_selectors.sort_by_key(|(pos, _)| *pos);
    
    for (idx, (pos, selector)) in sorted_selectors.iter().take(20).enumerate() {
        println!("  {}. Position {:#06x}: {}", idx + 1, pos, selector);
    }
    if sorted_selectors.len() > 20 {
        println!("  ... and {} more", sorted_selectors.len() - 20);
    }
    
    // Step 3: Check for access control patterns around SELFDESTRUCT
    println!("\n{}", "=".repeat(100));
    println!("STEP 3: ANALYZE ACCESS CONTROL AROUND SELFDESTRUCT");
    println!("{}", "=".repeat(100));
    
    for (idx, &sd_pos) in selfdestruct_locations.iter().enumerate().take(5) {
        println!("\n🎯 SELFDESTRUCT #{} at position {:#06x}:", idx + 1, sd_pos);
        
        // Look at 100 bytes before SELFDESTRUCT for access control patterns
        let start = sd_pos.saturating_sub(100);
        let window = &code[start..sd_pos];
        
        // Check for common access control opcodes
        let has_caller = window.iter().any(|&b| b == 0x33); // CALLER
        let has_origin = window.iter().any(|&b| b == 0x32); // ORIGIN
        let has_sload = window.iter().any(|&b| b == 0x54); // SLOAD (loading owner from storage)
        let has_eq = window.iter().any(|&b| b == 0x14); // EQ (comparison)
        let has_jumpi = window.iter().any(|&b| b == 0x57); // JUMPI (conditional jump)
        let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
        
        println!("  Access Control Indicators:");
        println!("    CALLER check: {}", if has_caller { "✓ FOUND" } else { "✗ MISSING" });
        println!("    ORIGIN check: {}", if has_origin { "✓ found" } else { "✗ none" });
        println!("    SLOAD (owner): {}", if has_sload { "✓ FOUND" } else { "✗ MISSING" });
        println!("    EQ (comparison): {}", if has_eq { "✓ FOUND" } else { "✗ MISSING" });
        println!("    JUMPI (conditional): {}", if has_jumpi { "✓ FOUND" } else { "✗ MISSING" });
        println!("    REVERT: {}", if has_revert { "✓ found" } else { "✗ none" });
        
        // Risk assessment
        let protection_level = [has_caller, has_sload, has_eq, has_jumpi].iter()
            .filter(|&&x| x).count();
        
        println!("\n  🚨 RISK ASSESSMENT:");
        match protection_level {
            0 => println!("    ⚠️  CRITICAL: NO ACCESS CONTROL DETECTED!"),
            1 => println!("    ⚠️  HIGH: Minimal protection (1 indicator)"),
            2 => println!("    ⚠️  MEDIUM: Partial protection (2 indicators)"),
            3 => println!("    ✓ LOW: Good protection (3 indicators)"),
            _ => println!("    ✓ MINIMAL: Strong protection (4+ indicators)"),
        }
        
        // Show bytecode context
        println!("\n  Bytecode context (20 bytes before SELFDESTRUCT):");
        print!("    ");
        let context_start = sd_pos.saturating_sub(20);
        for i in context_start..sd_pos {
            print!("{:02x} ", code[i]);
        }
        println!("[FF]");
    }
    
    // Step 4: Known dangerous function signatures
    println!("\n{}", "=".repeat(100));
    println!("STEP 4: CHECK FOR KNOWN DANGEROUS FUNCTION NAMES");
    println!("{}", "=".repeat(100));
    
    let dangerous_selectors = vec![
        ("0x00f55d9d", "kill()"),
        ("0x41c0e1b5", "destroy()"),
        ("0x8da5cb5b", "owner()"),
        ("0x715018a6", "renounceOwnership()"),
        ("0xf2fde38b", "transferOwnership(address)"),
        ("0x9870d7fe", "self_destruct()"),
        ("0x3ccfd60b", "withdraw()"),
        ("0x96e6d9c5", "close()"),
    ];
    
    println!("\nSearching for dangerous function selectors...\n");
    for (selector, name) in &dangerous_selectors {
        let found = function_selectors.values().any(|s| s == selector);
        if found {
            println!("  ⚠️  FOUND: {} {}", selector, name);
        }
    }
    
    // Step 5: Summary and recommendations
    println!("\n{}", "=".repeat(100));
    println!("📋 RECONNAISSANCE SUMMARY");
    println!("{}", "=".repeat(100));
    
    println!("\n✓ Total SELFDESTRUCT opcodes: {}", selfdestruct_locations.len());
    println!("✓ Function selectors found: {}", function_selectors.len());
    
    // Count unprotected instances
    let mut unprotected_count = 0;
    for &sd_pos in &selfdestruct_locations {
        let start = sd_pos.saturating_sub(100);
        let window = &code[start..sd_pos];
        let has_protection = window.iter().any(|&b| b == 0x33 || b == 0x54);
        if !has_protection {
            unprotected_count += 1;
        }
    }
    
    println!("\n⚠️  CRITICAL FINDINGS:");
    println!("   {} SELFDESTRUCT locations appear UNPROTECTED", unprotected_count);
    println!("   {} SELFDESTRUCT locations have some protection", 
        selfdestruct_locations.len() - unprotected_count);
    
    println!("\n🎯 NEXT STEPS FOR EXPLOITATION:");
    println!("   1. Test calling any 'destroy/kill' functions from non-owner address");
    println!("   2. Check if contract uses delegatecall (opcode 0xF4)");
    println!("   3. Look for uninitialized proxy patterns");
    println!("   4. Try to trigger SELFDESTRUCT via reentrancy");
    
    // Check for delegatecall
    let has_delegatecall = code.iter().any(|&b| b == 0xF4);
    if has_delegatecall {
        println!("\n   ⚠️  CONTRACT USES DELEGATECALL - Parity-style attack possible!");
    }
    
    println!("\n{}", "=".repeat(100));
    
    Ok(())
}
