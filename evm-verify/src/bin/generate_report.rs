use std::path::PathBuf;
use std::str::FromStr;
use clap::{Parser, ValueEnum};
use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use evm_verify::report::ReportFormat;
use evm_verify::ethereum::etherscan::EtherscanClient;
use anyhow::{Result, Context};
use dotenv::dotenv;
use std::env;
use ethers::types::Bytes;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Markdown,
    Html,
}

impl From<OutputFormat> for ReportFormat {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Json => ReportFormat::Json,
            OutputFormat::Markdown => ReportFormat::Markdown,
            OutputFormat::Html => ReportFormat::Html,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "EVM Bytecode Security Report Generator",
    about = "Analyzes EVM bytecode and generates security reports in various formats",
    version = "1.0.0"
)]
struct Args {
    /// Contract address to analyze
    #[arg(short, long, conflicts_with = "bytecode")]
    address: Option<String>,
    
    /// Raw bytecode to analyze (hex format)
    #[arg(short, long, conflicts_with = "address")]
    bytecode: Option<String>,
    
    /// Output file path
    #[arg(short, long, default_value = "report")]
    output: String,
    
    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Html)]
    format: OutputFormat,
    
    /// Contract name
    #[arg(short, long)]
    name: Option<String>,
    
    /// Network (mainnet, goerli, etc.) - only used with address
    #[arg(short = 'w', long, default_value = "mainnet")]
    network: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Load .env file if it exists
    dotenv().ok();
    
    // Get bytecode either from address or direct input
    let (bytecode, contract_name) = match (&args.address, &args.bytecode) {
        (Some(address), _) => {
            println!("Fetching bytecode for contract at address: {}", address);
            
            // Get Etherscan API key from environment
            let api_key = env::var("ETHERSCAN_API_KEY")
                .context("ETHERSCAN_API_KEY not found in environment variables")?;
            
            // Create Etherscan client
            let client = EtherscanClient::new(api_key, &args.network);
            
            // Fetch bytecode
            let bytecode = client.get_contract_bytecode(address).await?;
            
            // Use address as contract name if not provided
            let name = args.name.clone().unwrap_or_else(|| address.clone());
            
            (bytecode, name)
        },
        (_, Some(code)) => {
            // Process bytecode
            let bytecode_hex = code.trim();
            let bytecode_hex = if bytecode_hex.starts_with("0x") {
                &bytecode_hex[2..]
            } else {
                bytecode_hex
            };
            
            // Convert hex string to Bytes
            let bytecode = Bytes::from(
                hex::decode(bytecode_hex).context("Invalid bytecode hex string")?
            );
            
            // Use provided name or "Unknown"
            let name = args.name.clone().unwrap_or_else(|| "Unknown".to_string());
            
            (bytecode, name)
        },
        _ => {
            eprintln!("Error: Either --address or --bytecode must be provided");
            std::process::exit(1);
        }
    };
    
    println!("Analyzing bytecode...");
    
    // Create and configure analyzer
    let mut analyzer = BytecodeAnalyzer::new(bytecode);
    analyzer.set_test_mode(false); // Ensure we're not in test mode
    
    // Analyze bytecode
    let results = analyzer.analyze()?;
    
    println!("Analysis complete. Found {} potential security issues.", results.warnings.len());
    
    // Determine file extension
    let extension = match args.format {
        OutputFormat::Json => "json",
        OutputFormat::Markdown => "md",
        OutputFormat::Html => "html",
    };
    
    // Create output path
    let mut output_path = PathBuf::from_str(&args.output)?;
    if !output_path.extension().is_some() {
        output_path.set_extension(extension);
    }
    
    // Generate and save report
    analyzer.save_report_to_file(
        contract_name,
        ReportFormat::from(args.format),
        &output_path
    )?;
    
    println!("Report generated successfully: {}", output_path.display());
    
    Ok(())
}
