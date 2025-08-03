use clap::{Parser, Subcommand};
use evm_verify::analysis::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use ethers::types::H160;
use std::str::FromStr;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::Read;
use anyhow::{Result, Context, anyhow};
use std::collections::HashMap;
use serde_json::Value;

#[derive(Parser)]
#[command(name = "protocol-analyzer")]
#[command(about = "Analyze smart contract protocols for cross-contract vulnerabilities", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a collection of contracts as a protocol
    Analyze {
        /// Path to directory containing contract bytecode files or JSON artifacts
        #[arg(short, long)]
        dir: PathBuf,

        /// Output format (text, json, dot)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Path to JSON address map file (maps filenames to addresses)
        #[arg(short, long)]
        address_map: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Analyze { dir, format, output, address_map } => {
            analyze_protocol(dir, format, output.as_deref(), address_map.as_deref())?;
        }
    }

    Ok(())
}

/// Analyze a protocol from a directory of contract files
fn analyze_protocol(
    dir: &Path, 
    format: &str, 
    output: Option<&Path>, 
    address_map_path: Option<&Path>
) -> Result<()> {
    println!("Analyzing protocol in directory: {}", dir.display());
    
    // Initialize protocol analyzer
    let mut protocol = ContractProtocol::new();
    
    // Load address mapping if provided
    let address_map = if let Some(map_path) = address_map_path {
        load_address_map(map_path)?
    } else {
        HashMap::new()
    };
    
    // Find all contract files
    let files = find_contract_files(dir)?;
    println!("Found {} contract files", files.len());
    
    // Process each contract file
    for file_path in files {
        let result = process_contract_file(&file_path, &mut protocol, &address_map);
        
        if let Err(e) = result {
            println!("Warning: Failed to process file {}: {}", file_path.display(), e);
        }
    }
    
    // Build call graph
    protocol.build_call_graph()?;
    
    // Analyze for vulnerabilities
    let findings = protocol.analyze()?;
    
    // Format and output results
    match format {
        "text" => {
            let text_report = generate_text_report(&findings, &protocol);
            
            if let Some(output_path) = output {
                fs::write(output_path, text_report)?;
                println!("Report written to {}", output_path.display());
            } else {
                println!("{}", text_report);
            }
        },
        "json" => {
            let json_report = generate_json_report(&findings);
            
            if let Some(output_path) = output {
                fs::write(output_path, json_report)?;
                println!("JSON report written to {}", output_path.display());
            } else {
                println!("{}", json_report);
            }
        },
        "dot" => {
            // DOT graph generation not available in current API
            println!("DOT graph export is not supported in the current implementation.");
            println!("Available formats: text, json");
        },
        _ => {
            return Err(anyhow!("Unsupported output format: {}", format));
        }
    }
    
    Ok(())
}

/// Find all contract files in a directory
fn find_contract_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    
    if !dir.is_dir() {
        return Err(anyhow!("Path is not a directory: {}", dir.display()));
    }
    
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() {
            // Recursively search subdirectories
            let mut subdir_files = find_contract_files(&path)?;
            result.append(&mut subdir_files);
        } else {
            // Check file extension
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                
                // Include bytecode files and Solidity artifacts
                if ext_str == "bin" || ext_str == "bytecode" || ext_str == "json" {
                    result.push(path);
                }
            }
        }
    }
    
    Ok(result)
}

/// Process a contract file and add it to the protocol
fn process_contract_file(
    file_path: &Path,
    protocol: &mut ContractProtocol,
    address_map: &HashMap<String, String>
) -> Result<()> {
    // Generate a deterministic address if not in map
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("Invalid file name"))?;
    
    // Get address from map or generate from filename
    let address_str = if let Some(addr) = address_map.get(file_name) {
        addr.clone()
    } else {
        // Use filename as seed for deterministic address
        format!("0x{:040x}", xxhash32(file_name.as_bytes(), 0) as u128)
    };
    
    // Parse address
    let address = H160::from_str(&address_str)
        .with_context(|| format!("Failed to parse address: {}", address_str))?;
    
    // Read bytecode based on file type
    let bytecode = read_contract_bytecode(file_path)?;
    
    // Add to protocol
    protocol.add_contract(address, bytecode)?;
    
    println!("Added contract {} as address {}", file_name, address);
    
    Ok(())
}

/// Read contract bytecode from file
fn read_contract_bytecode(file_path: &Path) -> Result<Vec<u8>> {
    let extension = file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();
    
    match extension.as_str() {
        "json" => {
            // Parse JSON artifact
            let json_content = fs::read_to_string(file_path)?;
            let json_value: Value = serde_json::from_str(&json_content)?;
            
            // Extract bytecode - handle different JSON formats
            let bytecode_hex = if let Some(bytecode) = json_value.get("bytecode") {
                bytecode.as_str().ok_or_else(|| anyhow!("Bytecode is not a string"))?
            } else if let Some(bytecode) = json_value.get("deployedBytecode") {
                bytecode.as_str().ok_or_else(|| anyhow!("Bytecode is not a string"))?
            } else if let Some(obj) = json_value.get("object") {
                obj.as_str().ok_or_else(|| anyhow!("Object is not a string"))?
            } else {
                return Err(anyhow!("No bytecode found in JSON"));
            };
            
            // Handle 0x prefix
            let bytecode_hex = bytecode_hex.trim_start_matches("0x");
            
            // Convert hex to bytes
            hex::decode(bytecode_hex).with_context(|| "Failed to decode hex bytecode")
        },
        "bin" | "bytecode" => {
            // Read raw binary data
            let mut file = File::open(file_path)?;
            let mut bytecode = Vec::new();
            file.read_to_end(&mut bytecode)?;
            Ok(bytecode)
        },
        _ => {
            Err(anyhow!("Unsupported file extension: {}", extension))
        }
    }
}

/// Load address mapping from JSON file
fn load_address_map(path: &Path) -> Result<HashMap<String, String>> {
    let json_content = fs::read_to_string(path)?;
    let map: HashMap<String, String> = serde_json::from_str(&json_content)?;
    Ok(map)
}

/// Generate a text report of findings
fn generate_text_report(findings: &[ProtocolFinding], _protocol: &ContractProtocol) -> String {
    let mut report = String::new();
    
    report.push_str(&format!("=== Protocol Analysis Report ===\n"));
    report.push_str(&format!("Found {} security findings\n\n", findings.len()));
    
    for finding in findings {
        report.push_str(&format!("\n🔍 Finding: {}\n", format_finding_kind(&finding.kind)));
        report.push_str(&format!("   Severity: {}\n", format_severity(&finding.severity)));
        report.push_str(&format!("   Description: {}\n", finding.description));
        
        // Show call path
        if !finding.call_path.is_empty() {
            report.push_str("   Call Path:\n     ");
            for (i, addr) in finding.call_path.iter().enumerate() {
                if i > 0 {
                    report.push_str(" -> ");
                }
                report.push_str(&format!("{}", addr));
            }
            report.push_str("\n");
        }
        
        report.push_str(&format!("   Remediation: {}\n", finding.remediation));
    }
    
    report
}

/// Generate a JSON report of findings
fn generate_json_report(findings: &[ProtocolFinding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "{}".to_string())
}

/// Format finding kind with color
fn format_finding_kind(kind: &ProtocolFindingKind) -> String {
    match kind {
        ProtocolFindingKind::CrossContractReentrancy => "Cross-Contract Reentrancy".to_string(),
        ProtocolFindingKind::InconsistentAccessControl => "Inconsistent Access Control".to_string(),
        ProtocolFindingKind::PrivilegeEscalation => "Privilege Escalation".to_string(),
        ProtocolFindingKind::ValueLeakage => "Value Leakage".to_string(),
        ProtocolFindingKind::StateInconsistency => "State Inconsistency".to_string(),
        ProtocolFindingKind::CircularDependency => "Circular Dependency".to_string(),
        ProtocolFindingKind::OracleManipulation => "Oracle Manipulation".to_string(),
        ProtocolFindingKind::FlashLoanAttackVector => "Flash Loan Attack Vector".to_string(),
        ProtocolFindingKind::UpgradeDependencyRisk => "Upgrade Dependency Risk".to_string(),
        ProtocolFindingKind::Other => "Other Protocol Issue".to_string(),
    }
}

/// Format severity with color  
fn format_severity(severity: &evm_verify::bytecode::security::SecuritySeverity) -> String {
    use evm_verify::bytecode::security::SecuritySeverity;
    
    match severity {
        SecuritySeverity::Critical => "CRITICAL".to_string(),
        SecuritySeverity::High => "HIGH".to_string(),
        SecuritySeverity::Medium => "MEDIUM".to_string(),
        SecuritySeverity::Low => "LOW".to_string(),
        SecuritySeverity::Info => "INFO".to_string(),
    }
}

/// Simple xxHash32 implementation for deterministic address generation
fn xxhash32(data: &[u8], seed: u32) -> u32 {
    const PRIME1: u32 = 2654435761;
    const PRIME2: u32 = 2246822519;
    const PRIME3: u32 = 3266489917;
    const PRIME4: u32 = 668265263;
    const PRIME5: u32 = 374761393;

    let mut h32 = seed.wrapping_add(PRIME5);
    h32 = h32.wrapping_add(data.len() as u32);

    let mut i = 0;
    while i + 4 <= data.len() {
        let mut val = u32::from_le_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
        val = val.wrapping_mul(PRIME3);
        val = val.rotate_left(17);
        val = val.wrapping_mul(PRIME4);
        h32 ^= val;
        h32 = h32.rotate_left(19);
        h32 = h32.wrapping_mul(PRIME1).wrapping_add(PRIME2);
        i += 4;
    }

    while i < data.len() {
        let val = data[i] as u32;
        h32 ^= val.wrapping_mul(PRIME5);
        h32 = h32.rotate_left(11);
        h32 = h32.wrapping_mul(PRIME1);
        i += 1;
    }

    h32 ^= h32 >> 15;
    h32 = h32.wrapping_mul(PRIME2);
    h32 ^= h32 >> 13;
    h32 = h32.wrapping_mul(PRIME3);
    h32 ^= h32 >> 16;

    h32
}
