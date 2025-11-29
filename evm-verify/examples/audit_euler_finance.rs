/// Euler Finance V2 Security Audit
/// Comprehensive analysis of Euler V2 core protocol contracts
/// Using all 134 vulnerability analyzers including cutting-edge 2024-2025 detectors

use evm_verify::analysis::comprehensive_analyzer::ComprehensiveAnalyzerBuilder;
use ethers::{
    providers::{Http, Provider, Middleware},
    types::{Address, Bytes},
};
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 EULER FINANCE V2 SECURITY AUDIT");
    println!("══════════════════════════════════════════════════════");
    println!("Analyzing with 134 vulnerability detectors");
    println!("Including 15 cutting-edge 2024-2025 analyzers");
    println!("Post-Euler V1 exploit - Enhanced security focus\n");

    // Connect to Ethereum mainnet
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;
    let provider = Arc::new(provider);

    // Euler Finance V2 Critical Contracts
    let contracts = vec![
        // === CORE PROTOCOL (Highest Priority) ===
        ("EVC (Ethereum Vault Connector)", "0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383"),
        ("eVault Factory", "0x29a56a1b8214D9Cf7c5561811750D5cBDb45CC8e"),
        ("eVault Implementation", "0x8Ff1C814719096b61aBf00Bb46EAd0c9A529Dd7D"),
        ("Protocol Config", "0x4cD6BF1D183264c02Be7748Cb5cd3A47d013351b"),
        ("Balance Tracker", "0x0D52d06ceB8Dcdeeb40Cfd9f17489B350dD7F8a3"),
        
        // === GOVERNANCE (Critical for Security) ===
        ("Security Council Multisig", "0xb3b84e8320250Afe7a5fb313Ee32B52982b73c53"),
        ("eVault Factory Governor", "0x2F13256E04022d6356d8CE8C53C7364e13DC1f3d"),
        ("Emergency Governor", "0x35400831044167E9E2DE613d26515eeE37e30a1b"),
        ("Factory Timelock", "0xfb034c1C6c7F42171b2d1Cb8486E0f43ED07A968"),
        
        // === TOKEN CONTRACTS ===
        ("EUL Token", "0xd9Fcd98c322942075A5C3860693e9f4f03AAE07b"),
        ("rEUL (Staked EUL)", "0xf3e621395fc714B90dA337AA9108771597b4E696"),
        
        // === LENDING/BORROWING CORE ===
        ("Oracle Router Factory", "0x70B3f6F61b7Bf237DF04589DdAA842121072326A"),
        ("Oracle Adapter Registry", "0xA084A7F49723E3cc5722E052CF7fce910E7C5Fe6"),
        ("IRM Registry", "0x0a64670763777E59898AE28d6ACb7f2062BF459C"),
        ("Kink IRM Factory", "0xcAe0A39B45Ee9C3213f64392FA6DF30CE034C9F9"),
        
        // === EULERSWAP (DEX Integration) ===
        ("EulerSwap V2 Factory", "0xD05213331221fAB8a3C387F2affBb605Bb04DF5F"),
        ("EulerSwap V2 Implementation", "0x8B0E044E364F2cE913799d53b300e15A6974DC97"),
        ("EulerSwap V2 Periphery", "0xD3a349EE0A21eA0A7E9513ac236ae614b5FD513E"),
        ("Swap Verifier", "0xae26485ACDDeFd486Fe9ad7C2b34169d360737c7"),
        
        // === RISK MANAGEMENT ===
        ("Risk Steward", "0xBdAa3FCc9983bD72feE0F7D017e02673896a976d"),
        ("Cap Risk Steward Factory", "0x93c233008971E878d60a7737657869ab746f3208"),
        ("Fee Flow Controller", "0xFcd3Db06EA814eB21C84304fC7F90798C00D1e32"),
        
        // === EULER EARN (Yield Aggregator) ===
        ("EulerEarn Factory", "0x59709B029B140C853FE28d277f83C3a65e308aF4"),
        ("EulerEarn Public Allocator", "0x8fdCb80a2894F0dC052c8d52D22544DC90274800"),
        
        // === PERIPHERY (Security Critical) ===
        ("Swap Router (Swapper)", "0x2Bba09866b6F1025258542478C39720A09B728bF"),
        ("External Vault Registry", "0xB3b30ffb54082CB861B17DfBE459370d1Cc219AC"),
        ("Terms of Use Signer", "0x9ba11Acd88B79b657BDbD00B6dE759718AaAdCbA"),
    ];

    let mut total_critical = 0;
    let mut total_high = 0;
    let mut total_medium = 0;
    let mut total_contracts_analyzed = 0;
    let mut high_risk_contracts = Vec::new();

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

        // Build comprehensive analyzer
        let analyzer = ComprehensiveAnalyzerBuilder::new(code.clone())
            .with_contract_address(address_str.to_string())
            .build();

        // Run comprehensive analysis
        println!("🔬 Running comprehensive analysis...");
        let result = analyzer.analyze();

        total_contracts_analyzed += 1;

        // Display results
        println!("\n📊 SECURITY ANALYSIS RESULTS:");
        println!("──────────────────────────────");
        println!("🔴 Critical: {}", result.security_summary.critical_count);
        println!("🟠 High:     {}", result.security_summary.high_count);
        println!("🟡 Medium:   {}", result.security_summary.medium_count);
        println!("🔵 Low:      {}", result.security_summary.low_count);
        println!("📈 Total:    {}", result.total_vulnerabilities);

        total_critical += result.security_summary.critical_count;
        total_high += result.security_summary.high_count;
        total_medium += result.security_summary.medium_count;

        // Track high-risk contracts
        if result.security_summary.critical_count > 50 || 
           (!result.reentrancy_vulnerabilities.is_empty() && 
            result.reentrancy_vulnerabilities.iter().any(|v| v.severity.to_string() == "Critical")) {
            high_risk_contracts.push((name.to_string(), result.security_summary.critical_count, result.security_summary.high_count));
        }

        // Highlight critical findings for Euler V2
        if result.security_summary.critical_count > 0 || result.security_summary.high_count > 0 {
            println!("\n🚨 HIGH-PRIORITY FINDINGS:");

            // Check for post-V1-exploit specific vulnerabilities
            if !result.reentrancy_vulnerabilities.is_empty() {
                println!("  ⚠️  REENTRANCY (V1 exploit type): {}", result.reentrancy_vulnerabilities.len());
            }
            if !result.oracle_manipulation_vulnerabilities.is_empty() {
                println!("  ⚠️  Oracle manipulation: {}", result.oracle_manipulation_vulnerabilities.len());
            }
            if !result.flash_loan_vulnerabilities.is_empty() {
                println!("  ⚠️  Flash loan exploits: {}", result.flash_loan_vulnerabilities.len());
            }
            if !result.economic_vulnerabilities.is_empty() {
                println!("  ⚠️  Economic attacks: {}", result.economic_vulnerabilities.len());
            }
            if !result.governance_vulnerabilities.is_empty() {
                println!("  ⚠️  Governance vulnerabilities: {}", result.governance_vulnerabilities.len());
            }
            if !result.centralization_risk_vulnerabilities.is_empty() {
                println!("  ⚠️  Centralization risks: {}", result.centralization_risk_vulnerabilities.len());
            }
            
            // New V2-specific risks
            if !result.cross_chain_vulnerabilities.is_empty() {
                println!("  ⚠️  Cross-chain bridge risks: {}", result.cross_chain_vulnerabilities.len());
            }
            if !result.layer2_vulnerabilities.is_empty() {
                println!("  ⚠️  L2 specific issues: {}", result.layer2_vulnerabilities.len());
            }
        }

        // Analysis metadata
        println!("\n📌 Analysis Metadata:");
        println!("  Confidence: {:.1}%", result.analysis_confidence * 100.0);
        println!("  Bytecode Coverage: {:.1}%", result.coverage_metrics.bytecode_coverage_percentage);
        println!("  Attack Vectors: {}", result.security_summary.attack_vectors_detected);
        println!("  Time Dependencies: {}", result.security_summary.time_dependencies_found);

        // Save detailed report
        let report_filename = format!("euler_audit_{}_{}.json", 
            name.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_"),
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

    // Final Summary
    println!("\n\n");
    println!("══════════════════════════════════════════════════════");
    println!("🏁 EULER FINANCE V2 AUDIT SUMMARY");
    println!("══════════════════════════════════════════════════════");
    println!("📊 Contracts Analyzed: {}", total_contracts_analyzed);
    println!("🔴 Total Critical:     {}", total_critical);
    println!("🟠 Total High:         {}", total_high);
    println!("🟡 Total Medium:       {}", total_medium);
    
    if !high_risk_contracts.is_empty() {
        println!("\n⚠️  HIGH-RISK CONTRACTS REQUIRING REVIEW:");
        println!("──────────────────────────────────────────────────────");
        for (name, critical, high) in high_risk_contracts {
            println!("  • {}: {} critical, {} high", name, critical, high);
        }
    }

    println!("\n📝 NOTE: Euler V1 suffered $197M exploit from donation attack + reentrancy.");
    println!("   V2 analysis focuses on these attack vectors plus new risks.");
    println!("\n✅ Audit complete! Review JSON reports for detailed findings.");
    println!("══════════════════════════════════════════════════════\n");

    Ok(())
}
