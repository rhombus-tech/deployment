/// Check if contract has functions to steal ERC20 tokens
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0b6a649f01fc7da4295443342c9f283bb968f3fa")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 TOKEN THEFT VULNERABILITY ANALYSIS");
    println!("{}", "=".repeat(100));
    println!("Contract: 0x0b6A649f01Fc7Da4295443342c9f283bB968f3fa");
    println!("{}", "=".repeat(100));
    
    let bytecode = code.to_vec();
    
    // Look for ERC20 transfer function calls
    // ERC20.transfer(address,uint256) = 0xa9059cbb
    // ERC20.transferFrom(address,address,uint256) = 0x23b872dd
    
    println!("\n📋 SEARCHING FOR ERC20 FUNCTION CALLS");
    println!("{}", "-".repeat(100));
    
    let transfer_selector = vec![0xa9, 0x05, 0x9c, 0xbb];
    let transfer_from_selector = vec![0x23, 0xb8, 0x72, 0xdd];
    
    let mut transfer_locations = Vec::new();
    let mut transfer_from_locations = Vec::new();
    
    // Search for transfer() calls
    for i in 0..bytecode.len().saturating_sub(4) {
        if bytecode[i..i+4] == transfer_selector {
            transfer_locations.push(i);
        }
        if bytecode[i..i+4] == transfer_from_selector {
            transfer_from_locations.push(i);
        }
    }
    
    println!("\n✅ Found {} ERC20.transfer() patterns", transfer_locations.len());
    println!("✅ Found {} ERC20.transferFrom() patterns", transfer_from_locations.len());
    
    if transfer_locations.is_empty() && transfer_from_locations.is_empty() {
        println!("\n❌ NO ERC20 TRANSFER FUNCTIONS FOUND");
        println!("   This contract CANNOT move ERC20 tokens!");
        println!("   Any tokens sent here are TRAPPED FOREVER");
    } else {
        println!("\n⚠️  Contract CAN call ERC20 transfer functions!");
        println!("   Checking if these are exploitable...");
        
        // Check if transfers are near SELFDESTRUCT
        for loc in &transfer_locations {
            println!("\n🔴 ERC20.transfer() at PC {:#06x}", loc);
            
            // Check context around transfer
            let start = loc.saturating_sub(50);
            let end = (*loc + 50).min(bytecode.len());
            let context = &bytecode[start..end];
            
            // Check for access control
            let has_caller = context.iter().any(|&b| b == 0x33); // CALLER
            let has_jumpi = context.iter().any(|&b| b == 0x57); // JUMPI
            
            if !has_caller || !has_jumpi {
                println!("   ⚠️  NO ACCESS CONTROL - POTENTIALLY EXPLOITABLE");
                println!("   Anyone might be able to call this transfer function");
            } else {
                println!("   ✅ Has conditional logic (may have access control)");
            }
        }
    }
    
    // Check for arbitrary CALL/DELEGATECALL
    println!("\n{}", "=".repeat(100));
    println!("📋 CHECKING FOR ARBITRARY EXTERNAL CALLS");
    println!("{}", "-".repeat(100));
    
    let mut call_locs = Vec::new();
    let mut delegatecall_locs = Vec::new();
    
    for (i, &byte) in bytecode.iter().enumerate() {
        if byte == 0xf1 {
            call_locs.push(i);
        }
        if byte == 0xf4 {
            delegatecall_locs.push(i);
        }
    }
    
    println!("\n✅ Found {} CALL operations", call_locs.len());
    println!("✅ Found {} DELEGATECALL operations", delegatecall_locs.len());
    
    if delegatecall_locs.is_empty() {
        println!("\n✅ No DELEGATECALL - safer");
    } else {
        println!("\n⚠️  DELEGATECALL found - could be dangerous!");
    }
    
    // THE KEY QUESTION
    println!("\n{}", "=".repeat(100));
    println!("🎯 CAN ATTACKER STEAL TOKENS?");
    println!("{}", "=".repeat(100));
    
    if transfer_locations.is_empty() && transfer_from_locations.is_empty() && call_locs.is_empty() {
        println!("\n❌ NO - Contract has NO token transfer capability");
        println!("\n📊 Conclusion:");
        println!("   • SELFDESTRUCT: Cannot transfer ERC20 tokens");
        println!("   • No transfer functions: Cannot move tokens");
        println!("   • Result: Tokens are PERMANENTLY TRAPPED");
        println!("\n⚠️  ANY TOKENS SENT TO THIS CONTRACT ARE LOST FOREVER");
    } else if !transfer_locations.is_empty() || !transfer_from_locations.is_empty() {
        println!("\n⚠️  MAYBE - Contract CAN transfer tokens");
        println!("\n📊 Attack Vector Analysis:");
        println!("   1. Check if transfer functions have access control");
        println!("   2. If NO access control → Attacker can drain tokens");
        println!("   3. Process:");
        println!("      a) Call vulnerable transfer function");
        println!("      b) Transfer tokens to attacker address");
        println!("      c) Then call SELFDESTRUCT for ETH");
        println!("\n🔧 NEXT STEP: Test if transfer functions are exploitable");
    } else {
        println!("\n⚠️  POSSIBLE - Contract has CALL capability");
        println!("\n📊 Attack Vector Analysis:");
        println!("   • Contract could call arbitrary contracts");
        println!("   • Might be able to call token.transfer() externally");
        println!("   • Depends on function parameters and access control");
    }
    
    // Function analysis
    println!("\n{}", "=".repeat(100));
    println!("🔑 EXPLOITABLE FUNCTIONS ANALYSIS");
    println!("{}", "=".repeat(100));
    
    // Look for function signatures that might transfer tokens
    let dangerous_patterns = vec![
        (vec![0xa9, 0x05, 0x9c, 0xbb], "transfer(address,uint256)"),
        (vec![0x23, 0xb8, 0x72, 0xdd], "transferFrom(address,address,uint256)"),
        (vec![0x42, 0x96, 0x6c, 0x68], "burn(uint256)"),
        (vec![0x40, 0xc1, 0x0f, 0x19], "mint(address,uint256)"),
        (vec![0x8d, 0xa5, 0xcb, 0x5c], "initialize(...)"),
    ];
    
    println!("\n🔍 Searching for dangerous function patterns...\n");
    
    for (pattern, name) in dangerous_patterns {
        let mut found = false;
        for i in 0..bytecode.len().saturating_sub(4) {
            if bytecode[i..i+4] == pattern {
                if !found {
                    println!("   ⚠️  Found pattern: {}", name);
                    found = true;
                }
            }
        }
    }
    
    println!("\n{}", "=".repeat(100));
    println!("💡 SUMMARY");
    println!("{}", "=".repeat(100));
    println!("\n📌 Key Points:");
    println!("   1. SELFDESTRUCT alone CANNOT steal ERC20 tokens");
    println!("   2. Tokens must be transferred BEFORE SELFDESTRUCT");
    println!("   3. Check if contract has exploitable transfer functions");
    println!("   4. If NO transfer capability → Tokens trapped forever");
    println!("   5. If transfer functions exist → Check access control");
    
    println!("\n🎯 Attack Scenario (If Exploitable):");
    println!("   Step 1: Call vulnerable transfer function");
    println!("           → token.transfer(attackerAddress, balance)");
    println!("   Step 2: Call SELFDESTRUCT");
    println!("           → selfdestruct(attackerAddress)");
    println!("   Result: Attacker gets tokens + ETH, contract destroyed");
    
    Ok(())
}
