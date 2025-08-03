use evm_verify::api::{EVMVerify, AnalysisConfig, Vulnerability};
use ethers::providers::{Provider, Http};
use ethers::types::{H160, BlockNumber};
use std::collections::HashMap;
use std::time::Instant;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔍 Scanning recent blocks for ALL vulnerabilities (any protocol)...");
    
    // Initialize provider - using WORKING public endpoint (confirmed active)
    let provider = Provider::<Http>::try_from("https://ethereum-rpc.publicnode.com")?;
    
    // Track vulnerability statistics
    let mut vulnerability_stats = HashMap::<String, u32>::new();
    let mut total_transactions = 0;
    let mut vulnerable_transactions = 0;
    
    // Target RECENT blocks with confirmed transactions (2025)
    let block_ranges = vec![
        (22_959_215, 22_959_220), // Recent blocks: 172+ transactions each
        (22_961_551, 22_961_556), // Recent blocks: 239+ transactions each  
        (22_967_250, 22_967_258), // Latest blocks: current activity
    ];
    
    for (start_block, end_block) in block_ranges {
        println!("🔎 Scanning blocks {}-{}", start_block, end_block);
        
        for block_num in start_block..=end_block {
            use ethers::middleware::Middleware;
            if let Ok(Some(block)) = provider.get_block_with_txs(BlockNumber::from(block_num)).await {
                println!("\n📦 Block {} ({} transactions)", block_num, block.transactions.len());
                
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    total_transactions += 1;
                    
                    // Analyze ALL transactions (not just specific protocols)
                    if !tx.input.is_empty() {
                        match scan_transaction_vulnerabilities(&tx.input).await {
                            Ok(vulnerabilities) => {
                                if !vulnerabilities.is_empty() {
                                    vulnerable_transactions += 1;
                                    println!("🚨 VULNERABILITIES DETECTED in tx {}:", tx_idx);
                                    
                                    for vuln in &vulnerabilities {
                                        println!("   ⚠️  {:?}: {}", vuln.vulnerability_type, vuln.description);
                                        println!("      Severity: {:?}", vuln.severity);
                                        println!("      Location: {:?}", vuln.location);
                                        
                                        // Track vulnerability statistics
                                        *vulnerability_stats.entry(format!("{:?}", vuln.vulnerability_type)).or_insert(0) += 1;
                                    }
                                    
                                    // Show transaction details
                                    if let Some(to_addr) = tx.to {
                                        println!("      Contract: {:?}", to_addr);
                                    }
                                    println!("      Gas: {}", tx.gas);
                                    println!("      Value: {} ETH", tx.value.as_u64() as f64 / 1e18);
                                    
                                    // Generate report for significant vulnerabilities
                                    let high_severity_count = vulnerabilities.iter()
                                        .filter(|v| matches!(v.severity, evm_verify::api::VulnerabilitySeverity::High | evm_verify::api::VulnerabilitySeverity::Critical))
                                        .count();
                                    
                                    if high_severity_count > 0 {
                                        create_vulnerability_report(
                                            block_num,
                                            tx_idx,
                                            "Unknown Protocol",
                                            &tx.to.unwrap_or_default(),
                                            &vulnerabilities
                                        ).await?;
                                    }
                                }
                            }
                            Err(e) => {
                                // Only show errors for interesting transactions (with significant input data)
                                if tx.input.len() > 4 {
                                    println!("   ❌ Analysis error for tx {}: {}", tx_idx, e);
                                }
                            }
                        }
                    }
                }
            }
            
            // Rate limiting to avoid overwhelming RPC
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    }
    
    // Print summary statistics
    println!("\n{}", "=".repeat(60));
    println!("📊 VULNERABILITY SCAN SUMMARY");
    println!("{}", "=".repeat(60));
    println!("Total transactions analyzed: {}", total_transactions);
    println!("Vulnerable transactions found: {}", vulnerable_transactions);
    
    if vulnerable_transactions > 0 {
        println!("Vulnerability rate: {:.2}%", (vulnerable_transactions as f64 / total_transactions as f64) * 100.0);
        
        println!("\n🚨 VULNERABILITY BREAKDOWN:");
        for (vuln_type, count) in vulnerability_stats {
            println!("   {}: {} occurrences", vuln_type, count);
        }
    } else {
        println!("✅ No vulnerabilities detected in scanned blocks");
    }
    
    println!("\n✅ Universal vulnerability scan complete!");
    Ok(())
}

async fn scan_transaction_vulnerabilities(input_data: &ethers::types::Bytes) -> Result<Vec<Vulnerability>> {
    let start = Instant::now();
    
    // Convert transaction input to bytecode format
    let bytecode = input_data.clone();
    
    let config = AnalysisConfig::default();
    let verifier = EVMVerify::with_config(config);
    
    // Perform analysis
    let analysis_result = verifier.analyze_bytecode(bytecode)?;
    
    let duration = start.elapsed();
    if duration.as_millis() > 100 {
        println!("   📊 Analysis completed in {:?}", duration);
    }
    
    Ok(analysis_result.vulnerabilities)
}

async fn create_vulnerability_report(
    block_number: u64,
    tx_index: usize,
    protocol_name: &str,
    contract_address: &H160,
    vulnerabilities: &[Vulnerability]
) -> Result<()> {
    use std::fs;
    
    let filename = format!("universal_vulnerability_block_{}_tx_{}.md", block_number, tx_index);
    
    let report_content = format!(
        "# Vulnerability Report - Block {} Transaction {}\n\n## Contract Information\n- **Protocol**: {}\n- **Contract Address**: {:?}\n- **Block Number**: {}\n- **Transaction Index**: {}\n- **Scan Date**: {}\n\n## Vulnerabilities Detected\n\n{}\n\n## Recommendations\n\n1. **Immediate Review**: This contract contains high-severity vulnerabilities\n2. **Security Audit**: Conduct comprehensive security audit\n3. **User Warning**: Consider warning users about potential risks\n4. **Protocol Update**: Notify protocol developers of issues\n\n---\n*Generated by zkEVM Universal Vulnerability Scanner*\n",
        block_number,
        tx_index,
        protocol_name,
        contract_address,
        block_number,
        tx_index,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        vulnerabilities.iter()
            .map(|v| format!(
                "\n### {} (Severity: {:?})\n- **Description**: {}\n- **Location**: {:?}\n- **Recommendation**: {}\n",
                format!("{:?}", v.vulnerability_type),
                v.severity,
                v.description,
                v.location,
                v.recommendation,
            ))
            .collect::<String>()
    );
    
    fs::write(&filename, report_content)?;
    println!("   📄 Report saved: {}", filename);
    
    Ok(())
}
