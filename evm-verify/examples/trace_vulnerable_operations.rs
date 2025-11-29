/// Trace vulnerable operations to find exploitable paths
/// Shows which integer overflows are near ETH transfers

use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = std::env::args().nth(1)
        .expect("Usage: cargo run --example trace_vulnerable_operations <address>");
    
    println!("\n🔍 TRACING VULNERABLE OPERATIONS");
    println!("{}", "=".repeat(100));
    println!("Contract: {}\n", address);
    
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let addr: Address = address.parse()?;
    let bytecode = provider.get_code(addr, None).await?;
    
    println!("📊 Bytecode size: {} bytes", bytecode.len());
    println!("💰 Checking for ETH transfer patterns...\n");
    
    // Find ETH transfer operations
    let eth_transfers = find_eth_transfers(&bytecode);
    println!("Found {} potential ETH transfer operations", eth_transfers.len());
    
    // Analyze the contract
    let analyzer = ComprehensiveSecurityAnalyzer::new(bytecode.to_vec());
    let result = analyzer.analyze();
    
    println!("\n🔢 INTEGER VULNERABILITIES: {}", result.integer_vulnerabilities.len());
    
    // Find high-confidence integer operations
    let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| v.confidence >= 0.85)
        .collect();
    
    println!("   High-confidence: {}", high_conf.len());
    
    // Check which vulnerable operations are near ETH transfers
    println!("\n{}", "=".repeat(100));
    println!("🎯 EXPLOITABLE PATHS (Integer ops near ETH transfers):");
    println!("{}", "=".repeat(100));
    
    let mut exploitable_count = 0;
    
    for vuln in &high_conf {
        // Check if this operation is within 200 bytes of an ETH transfer
        let near_transfer = eth_transfers.iter()
            .any(|&transfer_pc| {
                let distance = if transfer_pc > vuln.pc {
                    transfer_pc - vuln.pc
                } else {
                    vuln.pc - transfer_pc
                };
                distance < 200  // Within 200 bytes
            });
        
        if near_transfer {
            exploitable_count += 1;
            println!("\n🚨 EXPLOITABLE #{}", exploitable_count);
            println!("   PC: {}", vuln.pc);
            println!("   Operation: {:?}", vuln.operation);
            println!("   Confidence: {:.0}%", vuln.confidence * 100.0);
            println!("   Severity: {:?}", vuln.severity);
            
            // Find nearest ETH transfer
            if let Some(&nearest) = eth_transfers.iter()
                .min_by_key(|&&pc| {
                    if pc > vuln.pc {
                        pc - vuln.pc
                    } else {
                        vuln.pc - pc
                    }
                }) {
                let distance = if nearest > vuln.pc {
                    nearest - vuln.pc
                } else {
                    vuln.pc - nearest
                };
                println!("   → ETH transfer at PC {} (distance: {} bytes)", nearest, distance);
                
                if distance < 50 {
                    println!("   ⚠️  VERY CLOSE - Likely in same function!");
                }
            }
        }
    }
    
    if exploitable_count == 0 {
        println!("\n❌ No vulnerable operations found near ETH transfers");
        println!("   This suggests:");
        println!("   • Integer overflows exist but may not drain ETH directly");
        println!("   • They might corrupt state/accounting instead");
        println!("   • Contract may have other value extraction mechanisms");
    } else {
        println!("\n{}", "=".repeat(100));
        println!("✅ Found {} potentially exploitable integer operations", exploitable_count);
        println!("\n🎯 ATTACK STRATEGY:");
        println!("   1. Reverse engineer functions containing these PCs");
        println!("   2. Craft inputs to trigger overflow at vulnerable MUL");
        println!("   3. Trigger ETH transfer with inflated value");
        println!("   4. Drain contract balance");
        println!("\n💰 Potential value at risk: Contract balance");
    }
    
    // Additional analysis: Check for SELFDESTRUCT
    println!("\n{}", "=".repeat(100));
    println!("🔍 ADDITIONAL RISK FACTORS:");
    println!("{}", "=".repeat(100));
    
    let has_selfdestruct = bytecode.iter().any(|&b| b == 0xFF);
    if has_selfdestruct {
        println!("⚠️  SELFDESTRUCT found - contract can be destroyed");
    }
    
    let has_delegatecall = bytecode.iter().any(|&b| b == 0xF4);
    if has_delegatecall {
        println!("⚠️  DELEGATECALL found - arbitrary code execution possible");
    }
    
    let call_count = bytecode.iter().filter(|&&b| b == 0xF1).count();
    println!("📞 CALL operations: {} (external calls)", call_count);
    
    Ok(())
}

fn find_eth_transfers(bytecode: &[u8]) -> Vec<usize> {
    let mut transfers = Vec::new();
    let mut pc = 0;
    
    while pc < bytecode.len() {
        let opcode = bytecode[pc];
        
        // Look for CALL (0xF1) which is used for ETH transfers
        // Pattern: CALL(gas, address, value, ...)
        if opcode == 0xF1 {
            transfers.push(pc);
        }
        
        // Look for TRANSFER pattern: PUSH value, PUSH address, CALL
        // This is more specific to ETH transfers with value
        if opcode >= 0x60 && opcode <= 0x7F {
            let push_size = (opcode - 0x5F) as usize;
            // Check if followed by another PUSH then CALL
            let next_pc = pc + 1 + push_size;
            if next_pc < bytecode.len() {
                let next_op = bytecode[next_pc];
                if next_op >= 0x60 && next_op <= 0x7F {
                    let next_push_size = (next_op - 0x5F) as usize;
                    let call_pc = next_pc + 1 + next_push_size;
                    if call_pc < bytecode.len() && bytecode[call_pc] == 0xF1 {
                        // This looks like a value transfer!
                        if !transfers.contains(&call_pc) {
                            transfers.push(call_pc);
                        }
                    }
                }
            }
        }
        
        pc += 1;
        // Skip PUSH data
        if opcode >= 0x60 && opcode <= 0x7F {
            let push_bytes = (opcode - 0x5F) as usize;
            pc += push_bytes;
        }
    }
    
    transfers.sort();
    transfers.dedup();
    transfers
}
