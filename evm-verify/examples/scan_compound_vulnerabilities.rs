use evm_verify::api::{EVMVerify, AnalysisConfig, Vulnerability, VulnerabilityType};

use ethers::providers::{Provider, Http};
use ethers::types::{H160, BlockNumber};
use std::collections::HashMap;
use std::time::Instant;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔍 Scanning recent blocks for CURRENT vulnerabilities...");
    
    // Initialize provider - using public endpoint
    let provider = Provider::<Http>::try_from("http://localhost:8545")?;
    
    // Known Compound Finance contract addresses
    let compound_contracts = HashMap::from([
        ("0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "Compound Comptroller"),
        ("0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643", "Compound cDAI"),
        ("0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5", "Compound cETH"), 
        ("0x39AA39c021dfbaE8faC545936693aC917d5E7563", "Compound cUSDC"),
        ("0xf650C3d88D12dB855b8bf7D11Be6C55A4e07dCC9", "Compound cUSDT"),
        ("0xC11b1268C1A384e55C48c2391d8d480264A3A7F4", "Compound cWBTC"),
        ("0x70e36f6BF80a52b3B46b3aF8e106CC0ed743E8e4", "Compound cLEND"),
    ]);
    
    // Block ranges to scan (focusing on CURRENT 2024-2025 activity)
    let block_ranges = vec![
        (21_000_000, 21_000_010), // Recent 2024 blocks
        (21_500_000, 21_500_010), // Late 2024 blocks  
        (22_000_000, 22_000_010), // Current 2025 blocks
    ];
    
    for (start_block, end_block) in block_ranges {
        println!("🔎 Scanning blocks {}-{}", start_block, end_block);
        
        for block_num in start_block..=end_block {
            use ethers::middleware::Middleware;
            if let Ok(Some(block)) = provider.get_block_with_txs(BlockNumber::from(block_num)).await {
                println!("\n📦 Block {} ({} transactions)", block_num, block.transactions.len());
                
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    // Check if transaction interacts with Compound contracts
                    if let Some(to_addr) = tx.to {
                        let addr_str = format!("{:?}", to_addr).to_lowercase();
                        
                        for (compound_addr, contract_name) in &compound_contracts {
                            if addr_str.contains(&compound_addr.to_lowercase()) {
                                println!("💰 Found Compound interaction: {} (tx {})", contract_name, tx_idx);
                                
                                // Analyze transaction data for vulnerabilities
                                if !tx.input.is_empty() {
                                    match scan_transaction_vulnerabilities(&tx.input).await {
                                        Ok(vulnerabilities) => {
                                            if !vulnerabilities.is_empty() {
                                                println!("🚨 VULNERABILITIES DETECTED:");
                                                for vuln in &vulnerabilities {
                                                    println!("Found {:?} vulnerability: {}", vuln.vulnerability_type, vuln.description);
                                                    println!("      Severity: {:?}", vuln.severity);
                                                    println!("      Location: {:?}", vuln.location);
                                                }
                                                
                                                // Create detailed vulnerability report
                                                create_vulnerability_report(
                                                    block_num,
                                                    tx_idx,
                                                    contract_name,
                                                    &to_addr,
                                                    &vulnerabilities
                                                ).await?;
                                            }
                                        }
                                        Err(e) => println!("   ❌ Analysis error: {}", e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Rate limiting to avoid overwhelming RPC
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
    
    println!("\n✅ Vulnerability scan complete!");
    Ok(())
}

async fn scan_transaction_vulnerabilities(input_data: &ethers::types::Bytes) -> Result<Vec<Vulnerability>> {
    let start = Instant::now();
    
    // Convert transaction input to bytecode format
    let bytecode = input_data.clone();
    
    let config = AnalysisConfig::default();
    let mut verifier = EVMVerify::with_config(config);
    
    // Perform analysis
    let analysis_result = verifier.analyze_bytecode(bytecode)?;
    
    // Extract vulnerabilities with focus on Compound-specific issues
    let mut compound_vulnerabilities = Vec::new();
    
    for vulnerability in analysis_result.vulnerabilities {
        match vulnerability.vulnerability_type {
            VulnerabilityType::IntegerOverflow |
            VulnerabilityType::IntegerUnderflow => {
                // This could be a Compound overflow/underflow issue
                compound_vulnerabilities.push(vulnerability.clone());
            }
            VulnerabilityType::AccessControl => {
                // Could be related to Compound's access control issues
                compound_vulnerabilities.push(vulnerability.clone());
            }
            _ => {}
        }
    }
    
    let duration = start.elapsed();
    println!("   📊 Analysis completed in {:?}", duration);
    
    Ok(compound_vulnerabilities)
}

fn is_compound_arithmetic_issue(description: &str) -> bool {
    let compound_patterns = [
        "interest",
        "borrow",
        "supply",
        "collateral",
        "liquidation",
        "exchange_rate",
        "compound",
        "ctoken",
    ];
    
    let desc_lower = description.to_lowercase();
    compound_patterns.iter().any(|pattern| desc_lower.contains(pattern))
}

async fn create_vulnerability_report(
    block_number: u64,
    tx_index: usize,
    contract_name: &str,
    contract_address: &H160,
    vulnerabilities: &[Vulnerability]
) -> Result<()> {
    let report_content = format!(
        r#"# Compound Finance Vulnerability Report

## Transaction Details
- **Block Number**: {}
- **Transaction Index**: {}
- **Contract**: {}
- **Address**: {:?}
- **Analysis Date**: {}

## Vulnerabilities Detected
{}"#,
        block_number,
        tx_index,
        contract_name,
        contract_address,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        vulnerabilities.iter()
            .map(|v| format!(
                "\n### {} (Severity: {:?})\n- **Description**: {}\n- **Affected Addresses**: {:?}\n",
                format!("{:?}", v.vulnerability_type),
                v.severity,
                v.description,
                format!("{:?}", v.location)
            ))
            .collect::<String>()
    );
    
    let filename = format!(
        "/Users/talzisckind/Downloads/deployment/compound_vulnerability_block_{}_tx_{}.md",
        block_number, tx_index
    );
    
    tokio::fs::write(&filename, report_content).await?;
    println!("   📄 Report saved: {}", filename);
    
    Ok(())
}
