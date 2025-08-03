#!/usr/bin/env cargo
/*!
Validate Compound Protocol Vulnerability Findings
===============================================

This test fetches the REAL Compound cToken contract from mainnet
and analyzes the specific vulnerabilities our system detected.

We'll cross-reference with:
1. Known Compound exploits (2021 liquidation bug, governance attacks)
2. Bytecode position 234 - the unchecked external call
3. MEV vulnerability patterns vs. legitimate design
4. Access control patterns vs. actual privilege escalation
*/

use anyhow::Result;
use ethers::{
    providers::{Http, Provider, Middleware},
    types::Address,
};
use std::str::FromStr;
use std::time::Instant;

use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::bytecode::precision_filter::PrecisionFilter;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔍 COMPOUND VULNERABILITY VALIDATION");
    println!("=====================================");
    
    let provider = Provider::<Http>::try_from(
        "https://ethereum-rpc.publicnode.com"
    )?;
    
    // Major Compound Protocol contracts
    let contracts = vec![
        (
            "0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643", // cDAI
            "Compound cDAI"
        ),
        (
            "0x39AA39c021dfbaE8faC545936693aC917d5E7563", // cUSDC  
            "Compound cUSDC"
        ),
        (
            "0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5", // cETH
            "Compound cETH"
        ),
    ];
    
    for (address, name) in contracts {
        if let Err(e) = fetch_and_analyze_contract(&provider, address, name).await {
            println!("❌ Error analyzing {}: {}", name, e);
            continue;
        }
    }
    
    println!("\n🎯 VALIDATION COMPLETE!");
    println!("Review findings to determine if vulnerabilities are:");
    println!("  ✅ REAL EXPLOITS - Market disruption validated");
    println!("  ❌ FALSE POSITIVES - Precision filter needs tuning");
    
    Ok(())
}

async fn fetch_and_analyze_contract(provider: &Provider<Http>, address: &str, name: &str) -> Result<()> {
    println!("\n📋 Analyzing {}...", name);
    println!("🔗 Address: {}", address);
    
    let address = match Address::from_str(address) {
        Ok(addr) => addr,
        Err(e) => {
            println!("❌ Failed to parse address {}: {}", address, e);
            return Err(e.into());
        }
    };
    
    println!("📋 Contract address: {}", address);
    
    let bytecode = match provider.get_code(address, None).await {
        Ok(code) => code,
        Err(e) => {
            println!("❌ Failed to fetch bytecode for {}: {}", address, e);
            return Err(e.into());
        }
    };
    
    println!("📋 Bytecode length: {} bytes", bytecode.len());
    
    if bytecode.is_empty() {
        println!("⚠️  Empty bytecode - contract may not exist or may be an EOA");
        return Ok(());
    }
    
    let start = Instant::now();
    
    // Analyze with our vulnerability scanner
    let mut analyzer = BytecodeAnalyzer::new(bytecode.clone());
    
    let analysis = match analyzer.analyze() {
        Ok(result) => result,
        Err(e) => {
            println!("❌ Analysis failed for {}: {}", name, e);
            return Err(e);
        }
    };
    let elapsed = start.elapsed();
    
    println!("⏱️  Analysis time: {}ms", elapsed.as_millis());
    println!("🔍 Total warnings: {}", analysis.security_warnings.len());
    
    if analysis.security_warnings.is_empty() {
        println!("✅ No vulnerabilities detected in {}", name);
        return Ok(());
    }
    
    println!("\n🚨 VULNERABILITIES FOUND IN {}:", name);
    println!("{}", "=".repeat(50));
    
    for (i, warning) in analysis.security_warnings.iter().enumerate() {
        println!("{}. 🔴 {}: {}", 
            i + 1, 
            format!("{:?}", warning.kind).to_uppercase(),
            warning.description
        );
        
        println!("   📍 Location: PC={}", warning.pc);
        
        if format!("{:?}", warning.severity).contains("HIGH") {
            println!("   🚨 CRITICAL SEVERITY");
        }
        
        println!();
    }
    
    // Apply precision filtering
    let precision_filter = PrecisionFilter::new_startup_friendly();
    let filtered_warnings = precision_filter.filter_warnings(analysis.security_warnings.clone());
    
    println!("🎯 AFTER PRECISION FILTERING:");
    println!("Original warnings: {}", analysis.security_warnings.len());
    println!("Filtered warnings: {}", filtered_warnings.len());
    println!("False positive reduction: {:.1}%", 
        100.0 * (analysis.security_warnings.len() - filtered_warnings.len()) as f32 / analysis.security_warnings.len() as f32
    );
    
    if !filtered_warnings.is_empty() {
        println!("\n⚠️  HIGH-CONFIDENCE VULNERABILITIES REMAINING:");
        for warning in &filtered_warnings {
            println!("  • {}: {}", 
                format!("{:?}", warning.kind).to_uppercase(),
                warning.description
            );
        }
    } else {
        println!("✅ All vulnerabilities filtered out - likely false positives");
    }
    
    // Check specific position 234 mentioned in logs
    if bytecode.len() > 234 {
        println!("\n🔬 ANALYZING POSITION 234 (Unchecked call):");
        let opcode_at_234 = bytecode[234];
        println!("Opcode at position 234: 0x{:02x}", opcode_at_234);
        
        // Check if it's actually a CALL opcode (0xf1) or related
        match opcode_at_234 {
            0xf1 => println!("  📞 CALL opcode detected - external call confirmed"),
            0xf2 => println!("  📞 CALLCODE opcode detected"),
            0xf4 => println!("  📞 DELEGATECALL opcode detected"),
            0xfa => println!("  📞 STATICCALL opcode detected"),
            _ => println!("  ❓ Not a call opcode - may be data or other instruction"),
        }
    }
    
    Ok(())
}
