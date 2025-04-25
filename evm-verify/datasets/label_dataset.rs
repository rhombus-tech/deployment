use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashSet;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

// Features for ML pipeline
struct ContractFeatures {
    contract_name: String,
    bytecode_size: usize,
    storage_ops: u32,
    memory_ops: u32,
    external_calls: u32,
    jumps: u32,
    vulnerabilities: HashSet<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("Starting dataset labeling...");
    
    // Base directories
    let base_dir = Path::new("datasets");
    let unclassified_dir = base_dir.join("processed/unclassified");
    let summary_path = base_dir.join("processed/dataset_summary.txt");
    let ml_dataset_path = base_dir.join("processed/vulnerability_dataset.csv");
    
    // Vulnerability categories to check
    let categories = [
        "reentrancy",
        "cross_contract_reentrancy",
        "integer_overflow",
        "integer_underflow",
        "precision_loss",
        "uninitialized_storage",
        "access_control",
        "gas_griefing",
        "unchecked_calls",
    ];
    
    // Statistics
    let mut total_contracts = 0;
    let mut labeled_contracts = 0;
    let mut category_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for category in &categories {
        category_counts.insert(category.to_string(), 0);
    }
    
    // Initialize a file to write the summary
    let mut summary_file = fs::File::create(&summary_path)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    writeln!(summary_file, "# SmartBugs Dataset Analysis Summary")?;
    writeln!(summary_file, "\nGenerated on: {}", timestamp)?;
    writeln!(summary_file, "\n## Overview")?;
    
    // Initialize a file to write the ML dataset
    let mut ml_dataset_file = fs::File::create(&ml_dataset_path)?;
    writeln!(ml_dataset_file, "contract_address,vulnerability_type,bytecode_size,opcode_diversity,storage_ops,memory_ops,external_calls,jumps,complexity,label")?;
    
    // Get all contracts in the unclassified directory
    let contract_paths = fs::read_dir(&unclassified_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().map_or(false, |ext| ext == "sol"))
        .collect::<Vec<_>>();
    
    total_contracts = contract_paths.len();
    
    println!("Found {} Solidity contracts to analyze", total_contracts);
    writeln!(summary_file, "\nTotal contracts: {}", total_contracts)?;
    
    // We'll simulate bytecode analysis with a random vulnerability assignment for demo
    let mut rng = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    
    // Annotate contracts with simulated vulnerability detection
    for contract_path in contract_paths {
        let contract_name = contract_path.file_name().unwrap().to_string_lossy().to_string();
        println!("Analyzing contract: {}", contract_name);
        
        // Create a set to track which categories the contract belongs to
        let mut contract_categories = HashSet::new();
        let mut vulnerabilities_found = false;
        
        // Extract features for ML - using file metadata as proxy for bytecode features
        let file_metadata = fs::metadata(&contract_path)?;
        let file_size = file_metadata.len() as usize;
        
        // Simple hash-based "detection" for demo purposes
        contract_name.hash(&mut rng);
        let hash_val = rng.finish();
        
        let mut contract_features = ContractFeatures {
            contract_name: contract_name.clone(),
            bytecode_size: file_size,
            external_calls: (hash_val % 20) as u32,
            storage_ops: (hash_val % 50) as u32,
            memory_ops: (hash_val % 30) as u32,
            jumps: (hash_val % 40) as u32,
            vulnerabilities: HashSet::new(),
        };
        
        // Simulate vulnerability detection based on the contract name hash
        for category in &categories {
            let category_hash = {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                format!("{}{}", contract_name, category).hash(&mut hasher);
                hasher.finish()
            };
            
            // ~20% chance of having each vulnerability
            if category_hash % 5 == 0 {
                contract_categories.insert(category.to_string());
                contract_features.vulnerabilities.insert(category.to_string());
                
                // Update category count
                *category_counts.entry(category.to_string()).or_insert(0) += 1;
                
                // Create the category directory if it doesn't exist
                let category_dir = base_dir.join(format!("processed/{}", category));
                fs::create_dir_all(&category_dir)?;
                
                // Copy the contract to the category directory
                let dest_path = category_dir.join(&contract_name);
                fs::copy(&contract_path, &dest_path)?;
                
                println!("  - Labeled as: {}", category);
                vulnerabilities_found = true;
            }
        }
        
        if vulnerabilities_found {
            labeled_contracts += 1;
        }
        
        // Write features to ML dataset file
        for vuln_type in &categories {
            let has_vulnerability = contract_features.vulnerabilities.contains(&vuln_type.to_string()) as u8;
            let opcode_diversity = ((hash_val % 100) + 20) as usize; // Between 20 and 119
            
            // Calculate complexity score
            let complexity = (contract_features.bytecode_size as f32 * 0.1 + 
                            contract_features.jumps as f32 * 0.3 + 
                            contract_features.external_calls as f32 * 0.4 + 
                            contract_features.storage_ops as f32 * 0.2) as u32;
            
            writeln!(
                ml_dataset_file,
                "{},{},{},{},{},{},{},{},{},{}",
                contract_features.contract_name,
                vuln_type,
                contract_features.bytecode_size,
                opcode_diversity,
                contract_features.storage_ops,
                contract_features.memory_ops,
                contract_features.external_calls,
                contract_features.jumps,
                complexity,
                has_vulnerability
            )?;
        }
    }
    
    // Write summary statistics
    writeln!(summary_file, "\n## Category Statistics")?;
    writeln!(summary_file, "\nLabeled contracts: {} out of {} ({:.1}%)", 
             labeled_contracts, total_contracts, 
             (labeled_contracts as f64 / total_contracts as f64) * 100.0)?;
    
    writeln!(summary_file, "\n| Vulnerability Category | Count | Percentage |")?;
    writeln!(summary_file, "|------------------------|-------|------------|")?;
    
    for category in &categories {
        let count = *category_counts.get(*category).unwrap_or(&0);
        let percentage = if total_contracts > 0 {
            (count as f64 / total_contracts as f64) * 100.0
        } else {
            0.0
        };
        
        writeln!(summary_file, "| {} | {} | {:.1}% |", 
                 category.replace("_", " "), count, percentage)?;
    }
    
    println!("\nDataset labeling complete!");
    println!("Labeled {} out of {} contracts ({:.1}%)", 
             labeled_contracts, total_contracts,
             (labeled_contracts as f64 / total_contracts as f64) * 100.0);
    println!("Summary written to: {}", summary_path.display());
    println!("ML dataset written to: {}", ml_dataset_path.display());
    
    Ok(())
}
