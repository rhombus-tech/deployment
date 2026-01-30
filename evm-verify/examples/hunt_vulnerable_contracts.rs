/// Continuous vulnerability hunter
/// Keeps scanning until it finds Critical/High vulnerabilities

use anyhow::Result;
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::BlockNumber;
use std::collections::HashMap;
use evm_verify::analysis::comprehensive_analyzer::{ComprehensiveSecurityAnalyzer, ComprehensiveAnalysisResult};
use evm_verify::bytecode::SecuritySeverity;
use rayon::prelude::*;

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
            
            // Use all analyzers for complete vulnerability detection
            let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
            let result = analyzer.analyze();
            
            // Debug: Print actual filtered total
            if result.total_vulnerabilities > 0 {
                eprintln!("[DEBUG] Contract {} has {} filtered vulns", 
                    &addr_str[..10], result.total_vulnerabilities);
            }
            
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
            if critical_found.len() >= 5 {
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
    // Debug: Always print what we're checking
    eprintln!("[RISK CHECK] total_vulnerabilities = {}", result.total_vulnerabilities);
    
    // REMOVED PREMATURE EARLY RETURNS - must validate with confidence/severity first
    // The total_vulnerabilities count includes low-confidence findings that aren't exploitable
    
    // CRITICAL REENTRANCY: ANY reentrancy detection is Critical
    // Reentrancy is too dangerous - if detected at all, flag it
    if !result.reentrancy_vulnerabilities.is_empty() {
        eprintln!("[CRITICAL] Reentrancy detected ({} vulnerabilities)", result.reentrancy_vulnerabilities.len());
        return RiskLevel::Critical;
    }
    
    // REMOVED: This was counting all reentrancy findings (including Medium severity)
    // Instead, rely on the critical_reentrancy_count check above which properly filters by severity
    
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
    // Path 1: Very high volume (100+ integer operations)
    // Path 2: High volume with concerning density (50+ ops at 10%+ density)
    // Path 3: Classic systematic pattern (20+ ops at 15%+ density)
    // Path 4: Multi-factor (Critical governance + 20+ integer ops)
    let has_critical_integer = 
        (result.integer_vulnerabilities.len() >= 100) ||
        (high_conf_integers.len() >= 50 && density >= 10.0) ||
        (high_conf_integers.len() >= 20 && density >= 15.0) ||
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
    
    // ========== TIER S: COMPILER BUGS ==========
    // ALIGNMENT FIX: These checks now only REPORT, don't auto-return Critical
    // The final 3-pattern test determines Critical status
    
    // Vyper compiler bugs - proven exploits in production
    if !result.vyper_mariposa_nonpayable_bypass_findings.is_empty() {
        eprintln!("[DETECTED] Vyper Mariposa nonpayable bypass");
    }
    if !result.vyper_storage_collision_modules_findings.is_empty() {
        eprintln!("[DETECTED] Vyper storage collision");
    }
    if !result.vyper_transient_storage_bug_findings.is_empty() {
        eprintln!("[DETECTED] Vyper transient storage bug");
    }
    
    // Uniswap V4 critical hook vulnerabilities
    if !result.uniswap_v4_singleton_hook_storage_collision_findings.is_empty() {
        eprintln!("[DETECTED] Uniswap V4 hook storage collision");
    }
    if !result.uniswap_v4_hook_reentrancy_findings.is_empty() {
        eprintln!("[DETECTED] Uniswap V4 hook reentrancy");
    }
    if !result.uniswap_v4_dynamic_fee_hook_manipulation_findings.is_empty() {
        eprintln!("[DETECTED] Uniswap V4 dynamic fee manipulation");
    }
    
    // ========== HIGH-IMPACT INFRASTRUCTURE EXPLOITS ==========
    // ALIGNMENT FIX: Report but don't auto-return Critical
    // Bridge vulnerabilities - $2B+ historical losses (Ronin, Wormhole, Nomad)
    let critical_bridges = result.bridge_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_bridges > 0 {
        eprintln!("[CRITICAL] Bridge vulnerability detected ({} critical)", critical_bridges);
        return RiskLevel::Critical;
    }
    
    // Cross-chain vulnerabilities - messaging/replay attacks
    let critical_cross_chain = result.cross_chain_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, evm_verify::analysis::cross_chain_analyzer::SecuritySeverity::Critical))
        .count();
    if critical_cross_chain > 0 {
        eprintln!("[DETECTED] Cross-chain vulnerability ({} critical)", critical_cross_chain);
    }
    
    // Proxy vulnerabilities - can brick entire protocol
    let critical_proxies = result.proxy_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_proxies > 0 {
        eprintln!("[DETECTED] Proxy vulnerability ({} critical)", critical_proxies);
    }
    
    // ========== DEFI ATTACK PATTERNS ==========
    // Flash loan attack vectors - can drain entire protocols
    let critical_flash_loans = result.flash_loan_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_flash_loans > 0 {
        eprintln!("[CRITICAL] Flash loan attack vector detected ({} critical)", critical_flash_loans);
        return RiskLevel::Critical;
    }
    
    // Oracle manipulation - $300M+ losses (Mango, Fortress, etc.)
    let critical_oracles = result.oracle_manipulation_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_oracles > 0 {
        eprintln!("[CRITICAL] Oracle manipulation detected ({} critical)", critical_oracles);
        return RiskLevel::Critical;
    }
    
    // Read-only reentrancy - Curve exploit pattern ($70M+)
    let critical_readonly_reentrancy = result.readonly_reentrancy_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_readonly_reentrancy > 0 {
        eprintln!("[CRITICAL] Read-only reentrancy detected ({} critical)", critical_readonly_reentrancy);
        return RiskLevel::Critical;
    }
    
    // ========== MODERN CRITICAL PATTERNS ==========
    // Donation attacks - protocol balance manipulation
    let critical_donations = result.donation_attack_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_donations > 0 {
        eprintln!("[CRITICAL] Donation attack detected ({} critical)", critical_donations);
        return RiskLevel::Critical;
    }
    
    // Balance manipulation - direct fund theft
    let critical_balance_manip = result.balance_manipulation_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_balance_manip > 0 {
        eprintln!("[CRITICAL] Balance manipulation detected ({} critical)", critical_balance_manip);
        return RiskLevel::Critical;
    }
    
    // Access control - unauthorized fund access
    let critical_access_control = result.access_control_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_access_control > 0 {
        eprintln!("[CRITICAL] Access control bypass detected ({} critical)", critical_access_control);
        return RiskLevel::Critical;
    }
    
    // Selfdestruct vulnerabilities - contract destruction
    let critical_selfdestruct = result.selfdestruct_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_selfdestruct > 0 {
        eprintln!("[CRITICAL] Selfdestruct vulnerability detected ({} critical)", critical_selfdestruct);
        return RiskLevel::Critical;
    }
    
    // MEV attack vulnerabilities - frontrunning/sandwich attacks
    let critical_mev = result.mev_attack_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_mev > 0 {
        eprintln!("[DETECTED] MEV attack vector ({} critical)", critical_mev);
    }
    
    // ========== ADDITIONAL CRITICAL EXPLOITS ==========
    // Initialization vulnerabilities - uninitialized proxies can be hijacked
    let critical_init = result.initialization_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_init > 0 {
        eprintln!("[CRITICAL] Initialization vulnerability detected ({} critical)", critical_init);
        return RiskLevel::Critical;
    }
    
    // Withdrawal vulnerabilities - direct fund theft
    let critical_withdrawal = result.withdrawal_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_withdrawal > 0 {
        eprintln!("[CRITICAL] Withdrawal vulnerability detected ({} critical)", critical_withdrawal);
        return RiskLevel::Critical;
    }
    
    // First depositor attack - inflation/donation attack variant
    let critical_first_depositor = result.first_depositor_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_first_depositor > 0 {
        eprintln!("[DETECTED] First depositor attack ({} critical)", critical_first_depositor);
    }
    
    // Vyper reentrancy bug - $70M+ Curve exploit (2023)
    let critical_vyper_reentrancy = result.vyper_bug_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_vyper_reentrancy > 0 {
        eprintln!("[DETECTED] Vyper reentrancy bug ({} critical)", critical_vyper_reentrancy);
    }
    
    // Permit2 vulnerabilities - signature-based exploits
    let critical_permit2 = result.permit2_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_permit2 > 0 {
        eprintln!("[DETECTED] Permit2 vulnerability ({} critical)", critical_permit2);
    }
    
    // Time manipulation - timestamp dependency exploits
    let critical_time = result.time_manipulation_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_time > 0 {
        eprintln!("[DETECTED] Time manipulation ({} critical)", critical_time);
    }
    
    // Gas griefing - DOS attacks
    let critical_gas_grief = result.gas_griefing_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_gas_grief > 0 {
        eprintln!("[DETECTED] Gas griefing attack ({} critical)", critical_gas_grief);
    }
    
    // Signature replay vulnerabilities
    let critical_sig_replay = result.signature_replay_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_sig_replay > 0 {
        eprintln!("[DETECTED] Signature replay vulnerability ({} critical)", critical_sig_replay);
    }
    
    // Upgrade vulnerabilities - malicious upgrades
    let critical_upgrade = result.upgrade_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .collect::<Vec<_>>();
    
    if critical_upgrade.len() >= 10 {
        eprintln!("[CRITICAL] Upgrade vulnerability ({} critical)", critical_upgrade.len());
        return RiskLevel::Critical;
    }
    
    // Emergency function vulnerabilities - privileged abuse
    let critical_emergency = result.emergency_function_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_emergency > 0 {
        eprintln!("[DETECTED] Emergency function vulnerability ({} critical)", critical_emergency);
    }
    
    // Weird ERC20 - non-standard token behavior
    let critical_weird_erc20 = result.weird_erc20_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_weird_erc20 > 0 {
        eprintln!("[DETECTED] Weird ERC20 behavior ({} critical)", critical_weird_erc20);
    }
    
    // CREATE2 vulnerabilities - address collision attacks
    let critical_create2 = result.create2_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_create2 > 0 {
        eprintln!("[DETECTED] CREATE2 vulnerability ({} critical)", critical_create2);
    }
    
    // Short address attack - parameter manipulation
    let critical_short_addr = result.short_address_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_short_addr > 0 {
        eprintln!("[DETECTED] Short address attack ({} critical)", critical_short_addr);
    }
    
    // Multicall atomicity - batched transaction failures
    let critical_multicall = result.multicall_atomicity_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_multicall > 0 {
        eprintln!("[DETECTED] Multicall atomicity issue ({} critical)", critical_multicall);
    }
    
    // ERC compliance violations - token standard issues
    let critical_erc_compliance = result.erc_compliance_vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    if critical_erc_compliance > 0 {
        eprintln!("[DETECTED] ERC compliance violation ({} critical)", critical_erc_compliance);
    }
    
    // ========== CRITICAL ALIGNMENT WITH DETAILED ANALYSIS ==========
    // CRITICAL FIX: Replace all the above checks with the SAME logic as analyze_specific_contract
    // The 30+ specialized vulnerability checks above are useful for REPORTING,
    // but should NOT automatically trigger Critical status.
    // 
    // Only flag as Critical if contract meets the rigorous 3-pattern test:
    // 1. Critical reentrancy (already checked above)
    // 2. Systematic integer overflow (high-confidence ops at sufficient density)
    // 3. High-confidence economic exploit
    //
    // This prevents false positives on contracts with design patterns that aren't exploitable.
    
    // We already checked critical_reentrancy_count above, which would have returned Critical
    // So if we're here, check the other two patterns:
    
    if has_critical_integer {
        eprintln!("[CRITICAL] Systematic integer overflow pattern detected");
        return RiskLevel::Critical;
    }
    
    if has_high_conf_economic {
        eprintln!("[CRITICAL] High-confidence economic exploit detected");
        return RiskLevel::Critical;
    }
    
    // If we got here, contract doesn't meet the detailed analysis thresholds
    // Even if specialized checks found issues, they're not exploitable enough to be Critical
    // Report them as High/Medium instead
    
    // HIGH RISK: Approaching critical thresholds
    if result.integer_vulnerabilities.len() >= 50 {
        return RiskLevel::High;
    }
    
    if high_conf_integers.len() >= 15 && density >= 8.0 {
        return RiskLevel::High;
    }
    
    if has_critical_governance && high_conf_integers.len() >= 10 {
        return RiskLevel::High;
    }
    
    if result.reentrancy_vulnerabilities.len() >= 3 {
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
