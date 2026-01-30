use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0b6a649f01fc7da4295443342c9f283bb968f3fa")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 SELFDESTRUCT EXPLOIT ANALYSIS");
    println!("{}", "=".repeat(100));
    println!("Contract: 0x0b6A649f01Fc7Da4295443342c9f283bB968f3fa");
    println!("Bytecode: {} bytes", code.len());
    println!("{}", "=".repeat(100));
    
    let bytecode = code.to_vec();
    
    // Find all SELFDESTRUCT opcodes (0xFF)
    let mut selfdestruct_locations = Vec::new();
    for (i, &byte) in bytecode.iter().enumerate() {
        if byte == 0xFF {
            selfdestruct_locations.push(i);
        }
    }
    
    println!("\n📍 SELFDESTRUCT LOCATIONS FOUND: {}", selfdestruct_locations.len());
    println!("{}", "-".repeat(100));
    
    for (idx, location) in selfdestruct_locations.iter().enumerate() {
        println!("\n🔴 SELFDESTRUCT #{} at PC {:#06x}", idx + 1, location);
        
        // Analyze 100 bytes before SELFDESTRUCT for access control patterns
        let start = location.saturating_sub(100);
        let context = &bytecode[start..*location];
        
        // Check for access control patterns
        let has_caller_check = check_caller_validation(context);
        let has_owner_check = check_owner_validation(context);
        let has_conditional = check_conditional_logic(context);
        let has_revert = check_revert_pattern(context);
        
        println!("  └─ Access Control Analysis:");
        println!("     ├─ CALLER check (msg.sender): {}", if has_caller_check { "✅ YES" } else { "❌ NO" });
        println!("     ├─ Owner validation: {}", if has_owner_check { "✅ YES" } else { "❌ NO" });
        println!("     ├─ Conditional logic: {}", if has_conditional { "✅ YES" } else { "❌ NO" });
        println!("     └─ Revert on failure: {}", if has_revert { "✅ YES" } else { "❌ NO" });
        
        // Show bytecode context
        println!("\n  └─ Bytecode Context (last 50 bytes before SELFDESTRUCT):");
        let display_start = location.saturating_sub(50);
        let display_context = &bytecode[display_start..*location];
        print!("     ");
        for (i, &byte) in display_context.iter().enumerate() {
            if i > 0 && i % 16 == 0 {
                print!("\n     ");
            }
            print!("{:02x} ", byte);
        }
        println!("\n     {:02x} ← SELFDESTRUCT", bytecode[*location]);
        
        // Risk assessment
        let risk_level = assess_risk(has_caller_check, has_owner_check, has_conditional, has_revert);
        println!("\n  └─ RISK LEVEL: {}", risk_level);
    }
    
    // Find function selectors that might lead to SELFDESTRUCT
    println!("\n{}", "=".repeat(100));
    println!("🔑 FUNCTION SELECTOR ANALYSIS");
    println!("{}", "-".repeat(100));
    
    let function_selectors = find_function_selectors(&bytecode);
    println!("\nFound {} potential function selectors:", function_selectors.len());
    
    for (selector, location) in function_selectors.iter().take(20) {
        println!("  • 0x{:08x} at PC {:#06x}", selector, location);
        
        // Check if this function path leads to SELFDESTRUCT
        if path_to_selfdestruct(&bytecode, *location, &selfdestruct_locations) {
            println!("    └─ ⚠️  May lead to SELFDESTRUCT");
        }
    }
    
    // Overall risk assessment
    println!("\n{}", "=".repeat(100));
    println!("📊 OVERALL RISK ASSESSMENT");
    println!("{}", "=".repeat(100));
    
    let protected_count = selfdestruct_locations.iter()
        .filter(|&&loc| {
            let start = loc.saturating_sub(100);
            let context = &bytecode[start..loc];
            let has_caller = check_caller_validation(context);
            let has_owner = check_owner_validation(context);
            has_caller || has_owner
        })
        .count();
    
    let unprotected_count = selfdestruct_locations.len() - protected_count;
    
    println!("\n✅ Protected SELFDESTRUCT operations: {}", protected_count);
    println!("❌ Unprotected SELFDESTRUCT operations: {}", unprotected_count);
    
    if unprotected_count > 0 {
        println!("\n🚨 CRITICAL VULNERABILITY DETECTED!");
        println!("   {} SELFDESTRUCT operation(s) have NO access control", unprotected_count);
        println!("\n⚠️  IMMEDIATE ACTIONS REQUIRED:");
        println!("   1. DO NOT interact with this contract");
        println!("   2. If you have funds deposited: WITHDRAW IMMEDIATELY");
        println!("   3. Contact contract owner/team about vulnerability");
        println!("   4. Report to relevant security channels");
    } else if protected_count > 0 {
        println!("\n⚠️  MODERATE RISK:");
        println!("   All SELFDESTRUCT operations appear to have access control");
        println!("   However, admin key compromise or rug pull is still possible");
        println!("\n💡 RECOMMENDATIONS:");
        println!("   1. Verify admin addresses and multisig setup");
        println!("   2. Check for timelock protection");
        println!("   3. Monitor for suspicious admin transactions");
        println!("   4. Consider migration to proxy pattern contracts");
    } else {
        println!("\n❓ UNCLEAR:");
        println!("   No SELFDESTRUCT operations detected or analysis inconclusive");
    }
    
    // Check current ETH balance
    let balance = provider.get_balance(addr, None).await?;
    println!("\n💰 Current Contract Balance: {} ETH", ethers::utils::format_ether(balance));
    
    if balance > ethers::types::U256::zero() && unprotected_count > 0 {
        println!("   🚨 FUNDS AT RISK: Contract holds ETH and has unprotected SELFDESTRUCT!");
    }
    
    Ok(())
}

fn check_caller_validation(context: &[u8]) -> bool {
    // CALLER (0x33) followed by comparison opcodes
    for i in 0..context.len().saturating_sub(2) {
        if context[i] == 0x33 { // CALLER
            // Check for EQ (0x14), ISZERO (0x15) nearby
            for j in i+1..std::cmp::min(i+10, context.len()) {
                if context[j] == 0x14 || context[j] == 0x15 {
                    return true;
                }
            }
        }
    }
    false
}

fn check_owner_validation(context: &[u8]) -> bool {
    // SLOAD (0x54) followed by CALLER (0x33) and comparison
    for i in 0..context.len().saturating_sub(5) {
        if context[i] == 0x54 && context[i+1] == 0x33 {
            if context[i+2] == 0x14 || context[i+2] == 0x15 {
                return true;
            }
        }
    }
    false
}

fn check_conditional_logic(context: &[u8]) -> bool {
    // JUMPI (0x57) indicates conditional branching
    context.iter().any(|&b| b == 0x57)
}

fn check_revert_pattern(context: &[u8]) -> bool {
    // REVERT (0xFD) or INVALID (0xFE)
    context.iter().any(|&b| b == 0xFD || b == 0xFE)
}

fn assess_risk(has_caller: bool, has_owner: bool, has_conditional: bool, has_revert: bool) -> String {
    match (has_caller || has_owner, has_conditional, has_revert) {
        (true, true, true) => "🟢 LOW - Strong access control detected".to_string(),
        (true, true, false) => "🟡 MEDIUM - Access control present but no revert".to_string(),
        (true, false, _) => "🟠 HIGH - Access control but no conditional check".to_string(),
        (false, _, _) => "🔴 CRITICAL - NO ACCESS CONTROL DETECTED".to_string(),
    }
}

fn find_function_selectors(bytecode: &[u8]) -> Vec<(u32, usize)> {
    let mut selectors = Vec::new();
    
    // Look for PUSH4 (0x63) followed by 4 bytes (function selector pattern)
    for i in 0..bytecode.len().saturating_sub(5) {
        if bytecode[i] == 0x63 {
            let selector = u32::from_be_bytes([
                bytecode[i+1],
                bytecode[i+2],
                bytecode[i+3],
                bytecode[i+4],
            ]);
            selectors.push((selector, i));
        }
    }
    
    selectors
}

fn path_to_selfdestruct(bytecode: &[u8], start: usize, selfdestruct_locs: &[usize]) -> bool {
    // Simple heuristic: check if there's a SELFDESTRUCT within 1000 bytes
    for &sd_loc in selfdestruct_locs {
        if sd_loc > start && sd_loc < start + 1000 {
            return true;
        }
    }
    false
}
