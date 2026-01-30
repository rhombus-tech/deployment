/// Convex Finance Security Audit
/// Comprehensive analysis of Convex Finance protocol contracts
/// Using all 850+ vulnerability analyzers including 50 new critical detectors (Dec 2025)

use evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalyzerBuilder;
use ethers::{
    providers::{Http, Provider, Middleware},
    types::{Address, Bytes},
};
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 CONVEX FINANCE SECURITY AUDIT");
    println!("══════════════════════════════════════════════════════");
    println!("Analyzing with 850+ vulnerability detectors");
    println!("Including 50 NEW critical analyzers (Dec 2025)");
    println!("  • Lending cap bypass • Oracle manipulation • Vault exploits");
    println!("  • MEV attacks • ZK vulnerabilities • Cross-chain issues\n");

    // Connect to Ethereum mainnet
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;
    let provider = Arc::new(provider);

    // Convex Finance Critical Contracts
    let contracts = vec![
        // Core Protocol
        ("Booster (Main Deposit)", "0xF403C135812408BFbE8713b5A23a04b3D48AAE31"),
        ("Voter Proxy", "0x989AEb4d175e16225E39E87d0D97A3360524AD80"),
        ("CVX Token", "0x4e3FBD56CD56c3e72c1403e103b45Db9da5B9D2B"),
        ("cvxCRV Token", "0x62B9c7356A2Dc64a1969e19C23e4f579F9810Aa7"),
        ("CRV Depositor", "0x8014595F2AB54cD7c604B00E9fb932176fDc86Ae"),
        
        // Factories & Rewards
        ("Reward Factory", "0xEdCCB35798fae4925718A43cc608aE136208aa8D"),
        ("Token Factory", "0x3c995e43E6ddD551E226F4c5544C77BfeD147aB9"),
        ("CVX Rewards", "0xCF50b810E57Ac33B91dCF525C6ddd9881B139332"),
        ("cvxCRV Rewards", "0x3Fe65692bfCD0e6CF84cB1E7d24108E434A7587e"),
        
        // Governance & Management
        ("Pool Manager", "0x782BcE229a8b603c99161e867A49D5426da37f95"),
        ("Multisig", "0xa3C5A1e09150B75ff251c1a7815A07182c3de2FB"),
        ("CVX Locker (vlCVX)", "0x72a19342e8F1838460eBFCCEf09F6585e32db86E"),
        
        // Treasury & Vaults
        ("Treasury Vault", "0x1389388d01708118b497f59521f6943Be2541bb7"),
        ("Arbitrator Vault", "0x25E12482a25CF36EC70fDA2A09C1ED077Fc21616"),
        
        // Utilities & Wrappers
        ("cvxCRV Wrapper", "0xaa0C3f5F7DFD688C6E646F66CD2a6B66ACdbE434"),
        ("Claim Zap v3", "0x3f29cB4111CbdA8081642DA1f75B3c12DECf2516"),
        
        // Frax Integration
        ("Frax Booster", "0xA2cF21b157b2f203e37b616b619f438B5aa86Ee5"),
        ("cvxFXS Token", "0xFEEf77d3f69374f66429C91d732A244f074bdf74"),
        ("cvxFXS Staking", "0x49b4d1dF40442f0C31b1BbAEA3EDE7c38e37E31a"),
        
        // FX Protocol Integration
        ("FX Booster", "0xAffe966B27ba3E4Ebb8A0eC124C7b7019CC762f8"),
        ("cvxFXN Token", "0x183395DbD0B5e93323a7286D1973150697FFFCB3"),
        
        // Prisma Integration
        ("Prisma Booster", "0x79a50f83E7AFf970CeAB5152a15461A4f1c3799E"),
        ("cvxPrisma Token", "0x34635280737b5BFe6c7DC2FC3065D60d66e78185"),
        ("cvxPrisma Staking", "0x0c73f1cFd5C9dFc150C8707Aa47Acbd14F0BE108"),
    ];

    let mut total_critical = 0;
    let mut total_high = 0;
    let mut total_medium = 0;
    let mut total_contracts_analyzed = 0;

    for (name, address_str) in contracts.iter() {
        println!("\n📋 Analyzing: {}", name);
        println!("📍 Address: {}", address_str);
        println!("─────────────────────────────────────────────────────");

        let address = match Address::from_str(address_str) {
            Ok(addr) => addr,
            Err(e) => {
                println!("❌ Invalid address: {}", e);
                continue;
            }
        };

        // Fetch contract bytecode
        let code: Vec<u8> = match provider.get_code(address, None).await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                println!("❌ Failed to fetch bytecode: {}", e);
                continue;
            }
        };

        if code.is_empty() {
            println!("⚠️  No bytecode found (EOA or not deployed)");
            continue;
        }

        println!("✅ Bytecode fetched: {} bytes", code.len());

        // Build comprehensive analyzer with ALL modules enabled
        let analyzer = ComprehensiveAnalyzerBuilder::new(code.clone())
            .with_contract_address(address_str.to_string())
            .build();

        // Run comprehensive analysis
        println!("🔬 Running comprehensive analysis...");
        let result = analyzer.analyze();

        total_contracts_analyzed += 1;

        // Display results
        println!("\n📊 SECURITY ANALYSIS RESULTS (VALIDATED):");
        println!("──────────────────────────────");
        println!("🔴 Critical: {}", result.security_summary.critical_count);
        println!("🟠 High:     {}", result.security_summary.high_count);
        println!("🟡 Medium:   {}", result.security_summary.medium_count);
        println!("🔵 Low:      {}", result.security_summary.low_count);
        println!("📈 Total:    {}", result.total_vulnerabilities);
        println!("\n💡 NOTE: Results filtered for confidence ≥75% + exploit validation");

        total_critical += result.security_summary.critical_count;
        total_high += result.security_summary.high_count;
        total_medium += result.security_summary.medium_count;

        // Highlight critical/high severity findings
        if result.security_summary.critical_count > 0 || result.security_summary.high_count > 0 {
            println!("\n🚨 HIGH-PRIORITY FINDINGS:");

            // === 50 NEW CRITICAL ANALYZERS (DEC 2025) ===
            if !result.supply_cap_bypass_vulnerabilities.is_empty() {
                println!("  🔴 Supply cap bypass: {}", result.supply_cap_bypass_vulnerabilities.len());
            }
            if !result.borrow_cap_bypass_vulnerabilities.is_empty() {
                println!("  🔴 Borrow cap bypass: {}", result.borrow_cap_bypass_vulnerabilities.len());
            }
            if !result.bad_debt_socialization_vulnerabilities.is_empty() {
                println!("  🔴 Bad debt socialization: {}", result.bad_debt_socialization_vulnerabilities.len());
            }
            if !result.recursive_borrowing_vulnerabilities.is_empty() {
                println!("  🔴 Recursive borrowing: {}", result.recursive_borrowing_vulnerabilities.len());
            }
            if !result.liquidation_threshold_gaming_vulnerabilities.is_empty() {
                println!("  🔴 Liquidation gaming: {}", result.liquidation_threshold_gaming_vulnerabilities.len());
            }
            if !result.isolated_market_vulnerabilities.is_empty() {
                println!("  🔴 Isolated market manipulation: {}", result.isolated_market_vulnerabilities.len());
            }
            if !result.chainlink_ocr2_vulnerabilities.is_empty() {
                println!("  🔴 Chainlink OCR2 issues: {}", result.chainlink_ocr2_vulnerabilities.len());
            }
            if !result.rebase_fee_combo_vulnerabilities.is_empty() {
                println!("  🔴 Rebase + fee-on-transfer: {}", result.rebase_fee_combo_vulnerabilities.len());
            }
            if !result.lst_withdrawal_queue_vulnerabilities.is_empty() {
                println!("  🔴 LST withdrawal queue: {}", result.lst_withdrawal_queue_vulnerabilities.len());
            }
            if !result.vault_performance_fee_vulnerabilities.is_empty() {
                println!("  🔴 Vault performance fee exploits: {}", result.vault_performance_fee_vulnerabilities.len());
            }

            // Check cutting-edge analyzer results
            if !result.restaking_vulnerabilities.is_empty() {
                println!("  ⚠️  Restaking vulnerabilities: {}", result.restaking_vulnerabilities.len());
            }
            if !result.liquid_staking_vulnerabilities.is_empty() {
                println!("  ⚠️  Liquid staking issues: {}", result.liquid_staking_vulnerabilities.len());
            }
            if !result.points_gaming_vulnerabilities.is_empty() {
                println!("  ⚠️  Points gaming risks: {}", result.points_gaming_vulnerabilities.len());
            }
            if !result.yield_tokenization_vulnerabilities.is_empty() {
                println!("  ⚠️  Yield tokenization issues: {}", result.yield_tokenization_vulnerabilities.len());
            }

            // Traditional vulnerabilities
            if !result.reentrancy_vulnerabilities.is_empty() {
                println!("  ⚠️  Reentrancy vulnerabilities: {}", result.reentrancy_vulnerabilities.len());
            }
            if !result.economic_vulnerabilities.is_empty() {
                println!("  ⚠️  Economic attack vectors: {}", result.economic_vulnerabilities.len());
            }
            if !result.upgrade_vulnerabilities.is_empty() {
                println!("  ⚠️  Upgrade risks: {}", result.upgrade_vulnerabilities.len());
            }
            if !result.flash_loan_vulnerabilities.is_empty() {
                println!("  ⚠️  Flash loan exploits: {}", result.flash_loan_vulnerabilities.len());
            }
            if !result.oracle_manipulation_vulnerabilities.is_empty() {
                println!("  ⚠️  Oracle manipulation: {}", result.oracle_manipulation_vulnerabilities.len());
            }
            if !result.governance_vulnerabilities.is_empty() {
                println!("  ⚠️  Governance vulnerabilities: {}", result.governance_vulnerabilities.len());
            }
            if !result.centralization_risk_vulnerabilities.is_empty() {
                println!("  ⚠️  Centralization risks: {}", result.centralization_risk_vulnerabilities.len());
            }
        }

        // Analysis metadata
        println!("\n📌 Analysis Metadata:");
        println!("  Confidence: {:.1}%", result.analysis_confidence * 100.0);
        println!("  Bytecode Coverage: {:.1}%", result.coverage_metrics.bytecode_coverage_percentage);
        println!("  Attack Vectors: {}", result.security_summary.attack_vectors_detected);

        // Save detailed report to file
        let report_filename = format!("convex_audit_{}_{}.json", 
            name.replace(" ", "_").replace("(", "").replace(")", ""),
            &address_str[2..10]
        );
        
        match std::fs::write(
            &report_filename,
            serde_json::to_string_pretty(&result)?
        ) {
            Ok(_) => println!("💾 Detailed report saved: {}", report_filename),
            Err(e) => println!("❌ Failed to save report: {}", e),
        }
    }

    // Summary
    println!("\n\n");
    println!("══════════════════════════════════════════════════════");
    println!("🏁 CONVEX FINANCE AUDIT SUMMARY");
    println!("══════════════════════════════════════════════════════");
    println!("📊 Contracts Analyzed: {}", total_contracts_analyzed);
    println!("🔴 Total Critical:     {}", total_critical);
    println!("🟠 Total High:         {}", total_high);
    println!("🟡 Total Medium:       {}", total_medium);
    println!("\n✅ Audit complete! Review JSON reports for detailed findings.");
    println!("══════════════════════════════════════════════════════\n");

    Ok(())
}
