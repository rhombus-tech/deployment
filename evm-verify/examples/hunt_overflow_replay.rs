/// Hunt for Integer Overflow and Signature Replay vulnerabilities
/// Focus on high-value targets with exploitable patterns

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{Address, U256};
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;
use evm_verify::bytecode::SecuritySeverity;
use std::collections::HashSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎯 VULNERABILITY HUNTER - Integer Overflow & Signature Replay");
    println!("{}", "=".repeat(100));
    println!("Scanning for high-value targets with exploitable patterns...");
    println!();
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let latest_block = provider.get_block_number().await?;
    println!("📦 Starting from block: {}", latest_block);
    println!("🎯 Target: Contracts with systematic integer overflow OR signature replay");
    println!("💰 Priority: High-value targets with tokens");
    println!();
    
    let mut found_targets = Vec::new();
    let mut scanned = 0;
    let max_targets = 10;
    
    // Scan backwards through blocks
    for block_num in (latest_block.as_u64() - 100..latest_block.as_u64()).rev() {
        if found_targets.len() >= max_targets {
            break;
        }
        
        let block = match provider.get_block(block_num).await {
            Ok(Some(b)) => b,
            _ => continue,
        };
        
        print!("📦 Block {}... ", block_num);
        
        let contracts: Vec<Address> = block.transactions.iter()
            .filter_map(|tx| {
                if tx.to.is_none() {
                    Some(tx.from)
                } else {
                    tx.to
                }
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .take(30)
            .collect();
        
        for addr in contracts {
            scanned += 1;
            
            let code = match provider.get_code(addr, None).await {
                Ok(c) if c.len() > 100 => c,
                _ => continue,
            };
            
            let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
            let result = analyzer.analyze();
            
            // Check for systematic integer overflow (pre-SafeMath contracts)
            let has_systematic_overflow = if !result.integer_vulnerabilities.is_empty() {
                let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
                    .filter(|v| v.confidence >= 0.85)
                    .collect();
                
                let density = if result.integer_vulnerabilities.len() > 0 {
                    (high_conf.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
                } else {
                    0.0
                };
                
                // Systematic pattern: 20+ operations with 10%+ high-confidence density
                high_conf.len() >= 20 && density >= 10.0
            } else {
                false
            };
            
            // Check for signature replay vulnerabilities (check attack_type instead of description)
            let has_signature_replay = result.governance_vulnerabilities.iter()
                .any(|v| format!("{:?}", v.attack_type).to_lowercase().contains("signature") 
                    || format!("{:?}", v.attack_type).to_lowercase().contains("replay"))
                && result.governance_vulnerabilities.iter()
                    .any(|v| matches!(v.severity, SecuritySeverity::Critical));
            
            if has_systematic_overflow || has_signature_replay {
                let addr_str = format!("0x{:x}", addr);
                
                // Check token balances
                let usdc_addr = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")?;
                let usdt_addr = Address::from_str("0xdac17f958d2ee523a2206206994597c13d831ec7")?;
                let dai_addr = Address::from_str("0x6B175474E89094C44Da98b954EedeAC495271d0F")?;
                
                // Simple balance check (USDC has 6 decimals, USDT 6, DAI 18)
                let eth_balance = provider.get_balance(addr, None).await.unwrap_or(U256::zero());
                let eth_value = eth_balance.as_u128() as f64 / 1e18 * 3300.0; // ETH @ $3300
                
                // Skip if no significant value
                if eth_value < 100.0 {
                    continue;
                }
                
                let vuln_type = if has_systematic_overflow {
                    "INTEGER_OVERFLOW"
                } else {
                    "SIGNATURE_REPLAY"
                };
                
                println!("\n\n🎉 Found {} vulnerability!", vuln_type);
                println!("   Contract: {}", addr_str);
                println!("   ETH Balance: ${:.2}", eth_value);
                println!("   Block: {}", block_num);
                
                if has_systematic_overflow {
                    let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
                        .filter(|v| v.confidence >= 0.85)
                        .collect();
                    let density = (high_conf.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0;
                    
                    println!("   Operations: {} total, {} high-conf", 
                             result.integer_vulnerabilities.len(), high_conf.len());
                    println!("   Density: {:.1}%", density);
                    println!("   ⚠️  SYSTEMATIC PATTERN - Likely pre-SafeMath contract");
                }
                
                if has_signature_replay {
                    println!("   Governance vulns: {}", result.governance_vulnerabilities.len());
                    println!("   ⚠️  Missing nonce/expiration in signature verification");
                }
                
                found_targets.push((addr_str, vuln_type.to_string(), eth_value));
            }
        }
        
        println!("{} contracts ✓", contracts.len());
        
        if scanned >= 500 {
            break;
        }
    }
    
    println!("\n{}", "=".repeat(100));
    println!("🏁 HUNT COMPLETE");
    println!("{}", "=".repeat(100));
    println!("\n📊 Statistics:");
    println!("   Contracts scanned: {}", scanned);
    println!("   Targets found: {}", found_targets.len());
    
    if !found_targets.is_empty() {
        println!("\n{}", "=".repeat(100));
        println!("🚨 VULNERABLE TARGETS FOUND");
        println!("{}", "=".repeat(100));
        
        for (i, (addr, vuln_type, value)) in found_targets.iter().enumerate() {
            println!("\n{}. {} (Block scan)", i+1, addr);
            println!("   Type: {}", vuln_type);
            println!("   ETH Value: ${:.2}", value);
            println!("   Priority: {}", if *value > 10000.0 { "HIGH" } else if *value > 1000.0 { "MEDIUM" } else { "LOW" });
        }
    }
    
    println!("\n{}", "=".repeat(100));
    
    Ok(())
}
