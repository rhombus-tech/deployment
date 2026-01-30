/// Deep analysis of Seaport to understand the 1,469 vulnerabilities
use ethers::providers::{Provider, Http, Middleware};
use ethers::types::Address;
use std::str::FromStr;
use evm_verify::analysis::comprehensive_analyzer::ComprehensiveSecurityAnalyzer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = "https://ethereum.publicnode.com";
    let provider = Provider::<Http>::try_from(rpc_url)?;
    
    let addr = Address::from_str("0x0000000071727de22e5e9d8baf0edac6f37da032")?;
    let code = provider.get_code(addr, None).await?;
    
    println!("\n🔍 DETAILED SEAPORT VULNERABILITY BREAKDOWN");
    println!("{}", "=".repeat(100));
    
    let analyzer = ComprehensiveSecurityAnalyzer::new(code.to_vec());
    let result = analyzer.analyze();
    
    println!("\n📊 TOTAL VULNERABILITIES: {}", result.total_vulnerabilities);
    println!("{}", "=".repeat(100));
    
    // Print breakdown of each category
    macro_rules! print_category {
        ($name:expr, $vec:expr) => {
            if !$vec.is_empty() {
                println!("\n{}: {} findings", $name, $vec.len());
            }
        };
    }
    
    print_category!("🔄 Reentrancy", result.reentrancy_vulnerabilities);
    print_category!("🔢 Integer", result.integer_vulnerabilities);
    print_category!("💰 Economic", result.economic_vulnerabilities);
    print_category!("🔧 Upgrade", result.upgrade_vulnerabilities);
    print_category!("🥪 Sandwich", result.sandwich_vulnerabilities);
    print_category!("⏰ Time", result.time_vulnerabilities);
    print_category!("🔗 Cross-contract", result.cross_contract_vulnerabilities);
    print_category!("🌉 Bridge", result.bridge_vulnerabilities);
    print_category!("📦 Protocol Dependency", result.protocol_dependency_vulnerabilities);
    print_category!("🏦 DeFi Primitive", result.defi_primitive_vulnerabilities);
    print_category!("📝 State Manipulation", result.state_manipulation_vulnerabilities);
    print_category!("⚡ MEV Attack", result.mev_attack_vulnerabilities);
    print_category!("🏛️ Governance", result.governance_vulnerabilities);
    print_category!("🔮 Oracle Infrastructure", result.oracle_infrastructure_vulnerabilities);
    print_category!("💧 LP Economic", result.lp_economic_vulnerabilities);
    print_category!("🦢 Black Swan", result.black_swan_vulnerabilities);
    print_category!("🎯 Multi-Vector", result.multi_vector_vulnerabilities);
    print_category!("🤖 AI Detected", result.ai_detected_vulnerabilities);
    print_category!("🏗️ Infrastructure", result.infrastructure_vulnerabilities);
    print_category!("⚛️ Atomic Composability", result.atomic_composability_vulnerabilities);
    print_category!("🔌 Protocol Integration", result.protocol_integration_vulnerabilities);
    print_category!("⚡ Advanced MEV", result.advanced_mev_vulnerabilities);
    print_category!("⛽ Gas Economic", result.gas_economic_vulnerabilities);
    print_category!("💸 Flash Loan", result.flash_loan_vulnerabilities);
    print_category!("📊 Data Integrity", result.data_integrity_vulnerabilities);
    print_category!("🔷 Layer2", result.layer2_vulnerabilities);
    print_category!("👤 Account Abstraction", result.account_abstraction_vulnerabilities);
    print_category!("🎯 Intent Protocol", result.intent_protocol_vulnerabilities);
    print_category!("🪝 Hooks/Callback", result.hooks_callback_vulnerabilities);
    print_category!("💹 Concentrated Liquidity", result.concentrated_liquidity_vulnerabilities);
    print_category!("🔒 Privacy/ZK", result.privacy_zk_vulnerabilities);
    print_category!("📉 Slippage", result.slippage_vulnerabilities);
    print_category!("🔗 DeFi Composability", result.defi_composability_risks);
    print_category!("🏃 Race Condition", result.race_condition_vulnerabilities);
    print_category!("💱 Arbitrage", result.arbitrage_vulnerabilities);
    print_category!("🎭 Proxy", result.proxy_vulnerabilities);
    print_category!("🧩 Composability Attacks", result.composability_attacks);
    print_category!("🔮 Oracle Manipulation", result.oracle_manipulation_vulnerabilities);
    print_category!("🚪 Access Control", result.access_control_vulnerabilities);
    print_category!("🛡️ MEV Protection", result.mev_protection_vulnerabilities);
    print_category!("🚫 Censorship", result.censorship_vulnerabilities);
    print_category!("⚖️ Invariant Violations", result.invariant_violations);
    print_category!("🔬 Precision", result.precision_vulnerabilities);
    print_category!("✍️ Signature Replay", result.signature_replay_vulnerabilities);
    
    println!("\n{}", "=".repeat(100));
    println!("\n✅ Analysis Complete - Categories with 0 findings not shown");
    
    Ok(())
}
