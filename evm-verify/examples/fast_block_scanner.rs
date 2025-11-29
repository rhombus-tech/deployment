/// Fast block vulnerability scanner with real-time progress
/// Optimized for speed with progress indicators

use anyhow::Result;
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::{BlockNumber, Address};
use std::collections::HashMap;
use evm_verify::analysis::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};
use evm_verify::bytecode::SecuritySeverity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🚀 FAST ETHEREUM BLOCK VULNERABILITY SCANNER");
    println!("{}", "=".repeat(100));
    
    // Connect to RPC with fallback
    let rpc_urls = vec![
        "https://ethereum.publicnode.com".to_string(),
        "https://rpc.ankr.com/eth".to_string(),
        "https://rpc.builder0x69.io".to_string(),
    ];

    let mut provider = None;
    for rpc_url in &rpc_urls {
        print!("🔗 Trying {}... ", rpc_url);
        match Provider::<Http>::try_from(rpc_url.as_str()) {
            Ok(p) => {
                if p.get_block_number().await.is_ok() {
                    println!("✅");
                    provider = Some(p);
                    break;
                } else {
                    println!("❌");
                }
            }
            Err(_) => println!("❌"),
        }
    }
    
    let provider = provider.ok_or_else(|| anyhow::anyhow!("All RPC providers failed"))?;
    let latest_block = provider.get_block_number().await?;
    println!("\n📦 Latest block: {}", latest_block);
    
    // Scan fewer blocks but faster
    let blocks_to_scan = 3;
    let contracts_per_block = 10;
    let start_block = latest_block.as_u64().saturating_sub(blocks_to_scan - 1);
    
    println!("\n⚡ Fast scan: {} blocks, {} contracts/block", blocks_to_scan, contracts_per_block);
    println!("{}", "=".repeat(100));
    
    let mut total_contracts = 0;
    let mut critical_vulns = Vec::new();
    let mut high_vulns = Vec::new();
    let mut medium_vulns = Vec::new();
    let mut scanned: HashMap<String, ComprehensiveAnalysisResult> = HashMap::new();
    
    let scan_start = std::time::Instant::now();
    
    for block_num in start_block..=latest_block.as_u64() {
        print!("\n📦 Block {}... ", block_num);
        
        let block = match provider.get_block_with_txs(BlockNumber::Number(block_num.into())).await {
            Ok(Some(b)) => {
                print!("✓ ({} txs) ", b.transactions.len());
                b
            }
            Ok(None) => {
                println!("❌ Not found");
                continue;
            }
            Err(e) => {
                println!("❌ Error: {}", e);
                continue;
            }
        };
        
        // Quick contract extraction
        let mut contracts = Vec::new();
        for tx in &block.transactions {
            if let Some(to) = tx.to {
                contracts.push(to);
            }
        }
        contracts.sort();
        contracts.dedup();
        
        print!("→ {} contracts ", contracts.len());
        
        // Scan top N contracts
        let to_scan = contracts_per_block.min(contracts.len());
        print!("→ scanning {}...", to_scan);
        
        let mut scanned_this_block = 0;
        for address in contracts.iter().take(to_scan) {
            let addr_str = format!("{:?}", address);
            if scanned.contains_key(&addr_str) {
                continue;
            }
            
            // Tiny delay to avoid rate limits
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            
            let code = match provider.get_code(*address, None).await {
                Ok(c) if !c.is_empty() => c,
                _ => continue,
            };
            
            // Quick analysis
            let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
            let result = analyzer.analyze();
            
            // Quick risk check
            let risk = calculate_risk(&result);
            
            scanned.insert(addr_str.clone(), result.clone());
            scanned_this_block += 1;
            total_contracts += 1;
            
            match risk {
                RiskLevel::Critical => {
                    critical_vulns.push((addr_str, result, risk));
                    print!("🔴");
                }
                RiskLevel::High => {
                    high_vulns.push((addr_str, result, risk));
                    print!("🟠");
                }
                RiskLevel::Medium => {
                    medium_vulns.push((addr_str, result, risk));
                    print!("🟡");
                }
                _ => print!("🟢"),
            }
        }
        
        println!(" ✓ ({} scanned)", scanned_this_block);
    }
    
    let scan_duration = scan_start.elapsed();
    
    // Results
    println!("\n{}", "=".repeat(100));
    println!("📊 FAST SCAN RESULTS");
    println!("{}", "=".repeat(100));
    
    println!("\n⏱️  Performance:");
    println!("   Scan time: {:.1}s", scan_duration.as_secs_f32());
    println!("   Contracts scanned: {}", total_contracts);
    println!("   Speed: {:.1} contracts/sec", total_contracts as f32 / scan_duration.as_secs_f32());
    
    println!("\n🎯 Findings:");
    println!("   🔴 Critical: {}", critical_vulns.len());
    println!("   🟠 High: {}", high_vulns.len());
    println!("   🟡 Medium: {}", medium_vulns.len());
    println!("   🟢 Clean/Low: {}", total_contracts - critical_vulns.len() - high_vulns.len() - medium_vulns.len());
    
    if total_contracts > 0 {
        let vuln_rate = ((critical_vulns.len() + high_vulns.len()) as f32 / total_contracts as f32) * 100.0;
        println!("\n   Critical+High rate: {:.1}%", vuln_rate);
    }
    
    // Show critical findings
    if !critical_vulns.is_empty() {
        println!("\n{}", "=".repeat(100));
        println!("🚨 CRITICAL VULNERABILITIES");
        println!("{}", "=".repeat(100));
        
        for (i, (addr, result, _)) in critical_vulns.iter().enumerate() {
            println!("\n{}. {}", i+1, &addr[..42]);
            print_quick_summary(result);
        }
    }
    
    // Show high findings
    if !high_vulns.is_empty() {
        println!("\n{}", "-".repeat(100));
        println!("⚠️  HIGH RISK VULNERABILITIES");
        println!("{}", "-".repeat(100));
        
        for (i, (addr, result, _)) in high_vulns.iter().enumerate() {
            println!("\n{}. {}", i+1, &addr[..42]);
            print_quick_summary(result);
        }
    }
    
    if critical_vulns.is_empty() && high_vulns.is_empty() {
        println!("\n✅ No Critical or High risk vulnerabilities detected");
        if !medium_vulns.is_empty() {
            println!("   ({} Medium-risk contracts have minor findings)", medium_vulns.len());
        }
    }
    
    println!("\n{}", "=".repeat(100));
    println!("✅ FAST SCAN COMPLETE");
    println!("{}", "=".repeat(100));
    
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Clean,
}

fn calculate_risk(result: &ComprehensiveAnalysisResult) -> RiskLevel {
    // Critical reentrancy
    let has_critical_reentrancy = result.reentrancy_vulnerabilities.iter()
        .any(|v| matches!(v.severity, SecuritySeverity::Critical));
    
    if has_critical_reentrancy {
        return RiskLevel::Critical;
    }
    
    // Integer overflow pattern
    let high_conf_integers: Vec<_> = result.integer_vulnerabilities.iter()
        .filter(|v| (matches!(v.severity, SecuritySeverity::Critical) && v.confidence > 0.80) || 
                    (matches!(v.severity, SecuritySeverity::High) && v.confidence >= 0.85) ||
                    v.confidence >= 0.95)
        .collect();
    
    let density = if result.integer_vulnerabilities.len() > 0 {
        (high_conf_integers.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
    } else {
        0.0
    };
    
    if high_conf_integers.len() >= 20 && density >= 10.0 {
        return RiskLevel::Critical;
    }
    
    // High confidence economic
    let has_high_conf_economic = result.economic_vulnerabilities.iter()
        .any(|v| v.detection_confidence >= 0.95 && 
                 matches!(v.severity, SecuritySeverity::Critical));
    
    if has_high_conf_economic {
        return RiskLevel::Critical;
    }
    
    // Medium/Low classification
    if result.total_vulnerabilities > 500 {
        RiskLevel::Medium
    } else if result.total_vulnerabilities > 100 {
        RiskLevel::Low
    } else {
        RiskLevel::Clean
    }
}

fn print_quick_summary(result: &ComprehensiveAnalysisResult) {
    println!("   Total findings: {}", result.total_vulnerabilities);
    
    if !result.reentrancy_vulnerabilities.is_empty() {
        let critical = result.reentrancy_vulnerabilities.iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .count();
        println!("   🔄 Reentrancy: {} ({} critical)", result.reentrancy_vulnerabilities.len(), critical);
    }
    
    if !result.integer_vulnerabilities.is_empty() {
        let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
            .filter(|v| v.confidence >= 0.85)
            .collect();
        let density = if result.integer_vulnerabilities.len() > 0 {
            (high_conf.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
        } else {
            0.0
        };
        println!("   🔢 Integer: {} total, {} high-conf ({:.1}% density)", 
                 result.integer_vulnerabilities.len(), high_conf.len(), density);
    }
    
    if !result.economic_vulnerabilities.is_empty() {
        let high_conf = result.economic_vulnerabilities.iter()
            .filter(|v| v.detection_confidence >= 0.90)
            .count();
        println!("   💰 Economic: {} ({} high-conf)", result.economic_vulnerabilities.len(), high_conf);
    }
}
