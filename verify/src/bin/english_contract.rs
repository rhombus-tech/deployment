// English Contract CLI - Process text files through the pipeline
use anyhow::Result;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use verify::english::*;
use verify::english::parser::EnglishContractParser;
use verify::english::validator::ContractValidator;
use verify::english::translator::LLMTranslator;

#[derive(Parser)]
#[command(name = "english-contract")]
#[command(about = "Translate English smart contracts to verified WASM")]
struct Args {
    /// Path to English contract text file
    #[arg(short, long)]
    input: PathBuf,
    
    /// Output path for Rust code (optional)
    #[arg(short = 'r', long)]
    rust_output: Option<PathBuf>,
    
    /// Output path for WASM bytecode (optional)
    #[arg(short = 'w', long)]
    wasm_output: Option<PathBuf>,
    
    /// Skip compilation (only generate Rust)
    #[arg(long)]
    rust_only: bool,
    
    /// Skip verification
    #[arg(long)]
    no_verify: bool,
    
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if it exists
    let _ = dotenv::dotenv();
    
    let args = Args::parse();
    
    // Print header
    println!("\n🚀 Aristo English Contract Compiler\n");
    println!("{}", "=".repeat(60));
    
    // Read input file
    if args.verbose {
        println!("\n📖 Reading contract from: {}", args.input.display());
    }
    
    let text = fs::read_to_string(&args.input)?;
    
    // Parse English contract
    println!("\n1️⃣  Parsing English contract...");
    let parser = EnglishContractParser::new();
    let contract = parser.parse(&text)?;
    
    println!("   ✅ Parsed: {}", contract.name);
    println!("      Functions: {}", contract.functions.len());
    println!("      State variables: {}", contract.state.len());
    println!("      Events: {}", contract.events.len());
    
    if args.verbose {
        println!("\n   📋 Functions:");
        for func in &contract.functions {
            println!("      • {}", func.name);
        }
    }
    
    // Validate
    println!("\n2️⃣  Validating contract...");
    let validator = ContractValidator::new();
    let validation = validator.validate(&contract)?;
    
    println!("   ✅ Validation passed");
    
    if !validation.warnings.is_empty() {
        println!("\n   ⚠️  Warnings:");
        for warning in &validation.warnings {
            println!("      • {}", warning);
        }
    }
    
    // Detect pattern and choose mode
    println!("\n3️⃣  Analyzing contract pattern...");
    use verify::english::pattern_detector::{PatternDetector, ContractPattern};
    let pattern = PatternDetector::detect(&contract);
    
    match pattern {
        ContractPattern::Custom => {
            println!("   🤖 Custom contract detected - using AI mode");
        }
        _ => {
            println!("   📋 {:?} pattern detected - using template mode", pattern);
            println!("   ✨ Guaranteed to compile!");
        }
    }
    
    // Generate Rust code
    println!("\n4️⃣  Generating Rust code...");
    let translator = LLMTranslator::new()?;
    
    let rust_code = if pattern != ContractPattern::Custom {
        use verify::english::template_generator::TemplateGenerator;
        TemplateGenerator::generate(&contract, &pattern)
    } else {
        if args.verbose {
            println!("   🤖 Calling Claude API...");
        }
        translator.translate_to_rust(&contract).await?
    };
    
    println!("   ✅ Translation complete ({} lines)", rust_code.lines().count());
    
    // Save Rust code if requested
    if let Some(rust_path) = &args.rust_output {
        fs::write(rust_path, &rust_code)?;
        println!("   💾 Saved Rust code to: {}", rust_path.display());
    }
    
    if args.verbose {
        println!("\n   📄 Generated Rust code preview:");
        println!("   {}", "-".repeat(58));
        for (i, line) in rust_code.lines().take(20).enumerate() {
            println!("   {:3} | {}", i + 1, line);
        }
        if rust_code.lines().count() > 20 {
            println!("   ... ({} more lines)", rust_code.lines().count() - 20);
        }
        println!("   {}", "-".repeat(58));
    }
    
    if args.rust_only {
        println!("\n✅ Rust generation complete (skipping compilation)");
        println!("\n{}", "=".repeat(60));
        return Ok(());
    }
    
    // Compile to WASM
    println!("\n5️⃣  Compiling to WASM...");
    let pipeline = EnglishContractPipeline::new()?;
    let wasm_bytes = pipeline.compile_rust_to_wasm(&rust_code)?;
    
    println!("   ✅ Compilation successful");
    println!("      WASM size: {} bytes ({:.1} KB)", wasm_bytes.len(), wasm_bytes.len() as f64 / 1024.0);
    
    // Save WASM if requested
    if let Some(wasm_path) = &args.wasm_output {
        fs::write(wasm_path, &wasm_bytes)?;
        println!("   💾 Saved WASM to: {}", wasm_path.display());
    }
    
    if args.no_verify {
        println!("\n✅ Compilation complete (skipping verification)");
        println!("\n{}", "=".repeat(60));
        return Ok(());
    }
    
    // Verify WASM
    println!("\n6️⃣  Running formal verification...");
    
    if args.verbose {
        println!("   🔍 Checking safety properties...");
    }
    
    match verify::verify_wasm(&wasm_bytes) {
        Ok(_) => {
            println!("   ✅ Verification PASSED");
            println!("\n      Safety Properties Verified:");
            println!("      • Memory safety (bounds checked)");
            println!("      • Type safety");
            println!("      • No memory leaks");
            println!("      • Deterministic execution");
            println!("      • Side-channel resistance");
            println!("      • Parameter validation (1024-byte limit)");
        }
        Err(e) => {
            println!("   ❌ Verification FAILED");
            println!("\n      Error: {}", e);
            println!("\n      The contract does not meet safety requirements.");
            println!("      Review the generated Rust code and try again.");
            std::process::exit(1);
        }
    }
    
    // Success!
    println!("\n{}", "=".repeat(60));
    println!("\n✅ SUCCESS! Contract is ready for deployment\n");
    println!("Summary:");
    println!("  • Contract: {}", contract.name);
    println!("  • Functions: {}", contract.functions.len());
    println!("  • WASM size: {} bytes", wasm_bytes.len());
    println!("  • Verification: PASSED ✅");
    
    if args.rust_output.is_none() {
        println!("\n💡 Tip: Use --rust-output to save the generated Rust code");
    }
    if args.wasm_output.is_none() {
        println!("💡 Tip: Use --wasm-output to save the compiled WASM");
    }
    
    println!("\n{}", "=".repeat(60));
    println!();
    
    Ok(())
}
