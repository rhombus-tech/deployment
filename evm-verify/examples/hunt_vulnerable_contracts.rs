/// Continuous vulnerability hunter
/// Keeps scanning until it finds Critical/High vulnerabilities

use anyhow::Result;
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::BlockNumber;
use std::collections::HashMap;
use evm_verify::analysis::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};
use evm_verify::bytecode::SecuritySeverity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🎯 VULNERABILITY HUNTER - Continuous Scanner");
    println!("{}", "=".repeat(100));
    println!("Scanning backwards through Ethereum history until we find vulnerable contracts...\n");
    
    // Connect to RPC
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let latest_block = provider.get_block_number().await?;
    
    println!("📦 Starting from block: {}", latest_block);
    println!("🎯 Goal: Find contracts with Critical or High risk vulnerabilities");
    println!("⚡ Strategy: Scan 30 contracts per block, go back in time\n");
    println!("{}", "=".repeat(100));
    
    let mut scanned_contracts = HashMap::new();
    let mut total_scanned = 0;
    let mut blocks_checked = 0;
    let mut critical_found = Vec::new();
    let mut high_found = Vec::new();
    
    let start_time = std::time::Instant::now();
    
    // Scan backwards from current block
    let mut current_block = latest_block.as_u64();
    let max_blocks = 50; // Go back up to 50 blocks
    let contracts_per_block = 30;
    
    'outer: for _ in 0..max_blocks {
        print!("📦 Block {}... ", current_block);
        
        let block = match provider.get_block_with_txs(BlockNumber::Number(current_block.into())).await {
            Ok(Some(b)) => b,
            _ => {
                println!("❌ Skip");
                current_block = current_block.saturating_sub(1);
                continue;
            }
        };
        
        // Extract contracts
        let mut contracts = Vec::new();
        for tx in &block.transactions {
            if let Some(to) = tx.to {
                contracts.push(to);
            }
        }
        contracts.sort();
        contracts.dedup();
        
        print!("{} contracts → ", contracts.len());
        blocks_checked += 1;
        
        // Scan contracts
        let mut scanned_this_block = 0;
        for address in contracts.iter().take(contracts_per_block) {
            let addr_str = format!("{:?}", address);
            
            if scanned_contracts.contains_key(&addr_str) {
                continue;
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
            
            let code = match provider.get_code(*address, None).await {
                Ok(c) if !c.is_empty() => c,
                _ => continue,
            };
            
            let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
            let result = analyzer.analyze();
            
            let risk = calculate_risk(&result);
            scanned_contracts.insert(addr_str.clone(), result.clone());
            scanned_this_block += 1;
            total_scanned += 1;
            
            match risk {
                RiskLevel::Critical => {
                    print!("🔴");
                    critical_found.push((addr_str, result, current_block));
                }
                RiskLevel::High => {
                    print!("🟠");
                    high_found.push((addr_str, result, current_block));
                }
                _ => print!("."),
            }
            
            // Check if we found enough
            if critical_found.len() >= 3 {
                println!("\n\n🎉 Found {} Critical vulnerabilities! Stopping scan.", critical_found.len());
                break 'outer;
            }
        }
        
        println!(" ✓ ({} scanned, {} total)", scanned_this_block, total_scanned);
        
        // Progress update every 5 blocks
        if blocks_checked % 5 == 0 {
            let elapsed = start_time.elapsed().as_secs();
            println!("   📊 Progress: {} blocks, {} contracts, {} Critical, {} High ({:.1}s)", 
                     blocks_checked, total_scanned, critical_found.len(), high_found.len(), elapsed);
        }
        
        current_block = current_block.saturating_sub(1);
    }
    
    let total_time = start_time.elapsed();
    
    // Final Results
    println!("\n{}", "=".repeat(100));
    println!("🏁 HUNT COMPLETE");
    println!("{}", "=".repeat(100));
    
    println!("\n📊 Statistics:");
    println!("   Blocks scanned: {}", blocks_checked);
    println!("   Contracts analyzed: {}", total_scanned);
    println!("   Time: {:.1}s ({:.1} contracts/sec)", 
             total_time.as_secs_f32(), 
             total_scanned as f32 / total_time.as_secs_f32());
    
    println!("\n🎯 Findings:");
    println!("   🔴 Critical: {}", critical_found.len());
    println!("   🟠 High: {}", high_found.len());
    
    if total_scanned > 0 {
        let crit_rate = (critical_found.len() as f32 / total_scanned as f32) * 100.0;
        let high_rate = (high_found.len() as f32 / total_scanned as f32) * 100.0;
        println!("\n   Critical rate: {:.2}%", crit_rate);
        println!("   High rate: {:.2}%", high_rate);
        println!("   Combined vuln rate: {:.2}%", crit_rate + high_rate);
    }
    
    // Show all critical vulnerabilities
    if !critical_found.is_empty() {
        println!("\n{}", "=".repeat(100));
        println!("🚨 CRITICAL VULNERABILITIES FOUND");
        println!("{}", "=".repeat(100));
        
        for (i, (addr, result, block)) in critical_found.iter().enumerate() {
            println!("\n{}. {} (Block: {})", i+1, &addr[..42], block);
            println!("{}", "-".repeat(100));
            print_detailed_analysis(result);
        }
    }
    
    // Show all high vulnerabilities
    if !high_found.is_empty() {
        println!("\n{}", "=".repeat(100));
        println!("⚠️  HIGH RISK VULNERABILITIES FOUND");
        println!("{}", "=".repeat(100));
        
        for (i, (addr, result, block)) in high_found.iter().enumerate() {
            println!("\n{}. {} (Block: {})", i+1, &addr[..42], block);
            println!("{}", "-".repeat(100));
            print_detailed_analysis(result);
        }
    }
    
    if critical_found.is_empty() && high_found.is_empty() {
        println!("\n❌ No Critical or High vulnerabilities found in {} contracts", total_scanned);
        println!("   This suggests:");
        println!("   • Modern mainnet contracts are generally safer");
        println!("   • Battle-tested contracts dominate recent blocks");
        println!("   • Our thresholds are appropriately conservative");
        println!("\n   To find more vulnerabilities:");
        println!("   • Scan older blocks (2016-2020 had more exploits)");
        println!("   • Lower thresholds (but increases false positives)");
        println!("   • Focus on new/unaudited contracts");
    }
    
    println!("\n{}", "=".repeat(100));
    
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
    // CRITICAL REENTRANCY: Real exploitable patterns (no effective guards)
    let critical_reentrancy_count = result.reentrancy_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical) && 
                    (v.protection_mechanisms.is_empty() || v.confidence >= 0.70))
        .count();
    
    if critical_reentrancy_count > 0 {
        return RiskLevel::Critical;
    }
    
    // INTEGER OVERFLOW: Enhanced detection with multiple paths
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
    
    // Check for critical governance issues
    let has_critical_governance = result.governance_vulnerabilities.iter()
        .any(|v| matches!(v.severity, SecuritySeverity::Critical));
    
    // CRITICAL INTEGER: Multiple paths (enhanced detection)
    // Path 1: Classic systematic pattern (20+ ops at 10%+ density)
    // Path 2: High volume (25+ ops at 9%+ density)
    // Path 3: Multi-factor (Critical governance + 20+ integer ops)
    let has_critical_integer = 
        (high_conf_integers.len() >= 20 && density >= 10.0) ||
        (high_conf_integers.len() >= 25 && density >= 9.0) ||
        (has_critical_governance && high_conf_integers.len() >= 20);
    
    if has_critical_integer {
        return RiskLevel::Critical;
    }
    
    // CRITICAL ECONOMIC: High-confidence economic exploits
    let has_high_conf_economic = result.economic_vulnerabilities.iter()
        .any(|v| v.detection_confidence >= 0.95 && 
                 matches!(v.severity, SecuritySeverity::Critical));
    
    if has_high_conf_economic {
        return RiskLevel::Critical;
    }
    
    // HIGH RISK: Approaching critical thresholds
    if high_conf_integers.len() >= 15 && density >= 8.0 {
        return RiskLevel::High;
    }
    
    if has_critical_governance && high_conf_integers.len() >= 10 {
        return RiskLevel::High;
    }
    
    // MEDIUM/LOW classification
    if result.total_vulnerabilities > 500 {
        RiskLevel::Medium
    } else if result.total_vulnerabilities > 100 {
        RiskLevel::Low
    } else {
        RiskLevel::Clean
    }
}

fn print_detailed_analysis(result: &ComprehensiveAnalysisResult) {
    println!("   📊 Total findings: {}", result.total_vulnerabilities);
    println!("   🎯 Analysis confidence: {:.1}%", result.analysis_confidence * 100.0);
    
    // Reentrancy details
    if !result.reentrancy_vulnerabilities.is_empty() {
        println!("\n   🔄 REENTRANCY ({}):", result.reentrancy_vulnerabilities.len());
        let critical: Vec<_> = result.reentrancy_vulnerabilities.iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();
        
        for (i, vuln) in critical.iter().take(3).enumerate() {
            println!("      {}. PC {}: {:?}, Conf: {:.0}%, Protection: {}", 
                     i+1, vuln.pc, vuln.severity, vuln.confidence * 100.0, 
                     if vuln.protection_mechanisms.is_empty() { "None" } else { "Yes" });
        }
        if critical.len() > 3 {
            println!("      ... and {} more", critical.len() - 3);
        }
    }
    
    // Integer details
    if !result.integer_vulnerabilities.is_empty() {
        let high_conf: Vec<_> = result.integer_vulnerabilities.iter()
            .filter(|v| v.confidence >= 0.85)
            .collect();
        
        let density = if result.integer_vulnerabilities.len() > 0 {
            (high_conf.len() as f32 / result.integer_vulnerabilities.len() as f32) * 100.0
        } else {
            0.0
        };
        
        println!("\n   🔢 INTEGER OVERFLOW:");
        println!("      Total operations: {}", result.integer_vulnerabilities.len());
        println!("      High-confidence: {}", high_conf.len());
        println!("      Vulnerability density: {:.1}%", density);
        
        if high_conf.len() >= 20 && density >= 10.0 {
            println!("      ⚠️  SYSTEMATIC PATTERN DETECTED - Above critical thresholds!");
        } else if high_conf.len() >= 15 && density >= 8.0 {
            println!("      ⚠️  ELEVATED RISK - Approaching critical thresholds");
        }
        
        // Show sample operations
        for (i, vuln) in high_conf.iter().take(5).enumerate() {
            println!("      {}. PC {}: {:?}, Conf: {:.0}%", 
                     i+1, vuln.pc, vuln.operation, vuln.confidence * 100.0);
        }
        if high_conf.len() > 5 {
            println!("      ... and {} more", high_conf.len() - 5);
        }
    }
    
    // Economic details
    if !result.economic_vulnerabilities.is_empty() {
        println!("\n   💰 ECONOMIC VULNERABILITIES ({}):", result.economic_vulnerabilities.len());
        let high_conf: Vec<_> = result.economic_vulnerabilities.iter()
            .filter(|v| v.detection_confidence >= 0.90)
            .collect();
        
        for (i, vuln) in high_conf.iter().take(3).enumerate() {
            println!("      {}. {:?}: {:?}, Conf: {:.0}%", 
                     i+1, vuln.attack_type, vuln.severity, vuln.detection_confidence * 100.0);
        }
        if high_conf.len() > 3 {
            println!("      ... and {} more", high_conf.len() - 3);
        }
    }
    
    // Governance details
    if !result.governance_vulnerabilities.is_empty() {
        println!("\n   🏛️  GOVERNANCE VULNERABILITIES ({}):", result.governance_vulnerabilities.len());
        let critical: Vec<_> = result.governance_vulnerabilities.iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();
        
        if !critical.is_empty() {
            println!("      ⚠️  {} CRITICAL governance issues detected!", critical.len());
            for (i, vuln) in critical.iter().take(3).enumerate() {
                println!("      {}. {:?}, Conf: {:.0}%", 
                         i+1, vuln.severity, vuln.detection_confidence * 100.0);
            }
            if critical.len() > 3 {
                println!("      ... and {} more", critical.len() - 3);
            }
        }
    }
}
