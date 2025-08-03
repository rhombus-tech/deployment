use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashMap;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Create directories if they don't exist
    let dataset_dir = PathBuf::from("datasets/smartbugs");
    let processed_dir = PathBuf::from("datasets/processed");
    
    fs::create_dir_all(&dataset_dir)?;
    fs::create_dir_all(&processed_dir)?;
    
    // Clone the SmartBugs repository
    println!("Cloning SmartBugs repository...");
    if !dataset_dir.join("contracts").exists() {
        let status = Command::new("git")
            .args(&["clone", "--depth=1", "https://github.com/smartbugs/smartbugs-wild.git", 
                    dataset_dir.to_str().unwrap()])
            .status()?;
            
        if !status.success() {
            return Err("Failed to clone SmartBugs repository".into());
        }
    } else {
        println!("SmartBugs repository already exists, skipping clone...");
    }
    
    // Process the dataset for ML
    println!("Processing dataset for ML...");
    process_dataset(&dataset_dir, &processed_dir)?;
    
    println!("Dataset ready at {}", processed_dir.display());
    Ok(())
}

fn process_dataset(source_dir: &Path, target_dir: &Path) -> Result<(), Box<dyn Error>> {
    // Create category directories that match our vulnerability types
    let categories = vec![
        "reentrancy", 
        "cross_contract_reentrancy",
        "precision_loss", 
        "uninitialized_storage",
        "gas_griefing",
        "integer_overflow",
        "integer_underflow",
        "access_control",
        "unchecked_calls"
    ];
    
    // Create directories for each category
    for category in &categories {
        let output_dir = target_dir.join(category);
        fs::create_dir_all(&output_dir)?;
    }
    
    // Create a directory for unclassified contracts
    let unclassified_dir = target_dir.join("unclassified");
    fs::create_dir_all(&unclassified_dir)?;
    
    // Process contracts from the SmartBugs dataset
    let contracts_dir = source_dir.join("contracts");
    if !contracts_dir.exists() {
        return Err(format!("Contracts directory not found: {}", contracts_dir.display()).into());
    }
    
    println!("Copying contracts to processed directory...");
    
    // Count how many contracts we process
    let mut processed_count = 0;
    
    // Just copy the first 100 contracts to start with for testing
    // In a real implementation, you'd process all contracts and use your vulnerability detectors
    if let Ok(entries) = fs::read_dir(&contracts_dir) {
        for (i, entry) in entries.enumerate() {
            if i >= 100 { // Limit to first 100 for now
                break;
            }
            
            if let Ok(entry) = entry {
                let path = entry.path();
                
                if path.is_file() && path.extension().map_or(false, |ext| ext == "sol") {
                    // For now, just copy to unclassified directory
                    // Later, you would analyze the contract and copy to appropriate category
                    if let Some(file_name) = path.file_name() {
                        let dest_path = unclassified_dir.join(file_name);
                        if let Err(e) = fs::copy(&path, &dest_path) {
                            println!("Warning: Failed to copy {}: {}", path.display(), e);
                            continue;
                        }
                        
                        processed_count += 1;
                    }
                }
            }
        }
    }
    
    println!("Processed {} contracts", processed_count);
    
    // Write a summary file
    let summary_path = target_dir.join("summary.txt");
    let summary_content = format!(
        "SmartBugs Dataset Summary\n\
         ========================\n\n\
         Total contracts: {}\n\n\
         These contracts need to be processed with EVM-Verify vulnerability detectors\n\
         to classify them into the following categories:\n\n{}\n\
         \n\
         Instructions:\n\
         1. Implement a script that runs each contract through the vulnerability detectors\n\
         2. Move contracts to appropriate category directories based on detection results\n\
         3. Use the labeled dataset for ML training\n",
         processed_count,
         categories.join("\n")
    );
    
    fs::write(summary_path, summary_content)?;
    
    Ok(())
}

// Function to compile a dataset utility module
fn create_dataset_utility(base_dir: &Path) -> Result<(), Box<dyn Error>> {
    let lib_dir = base_dir.join("src");
    fs::create_dir_all(&lib_dir)?;
    
    let lib_rs_path = lib_dir.join("lib.rs");
    let lib_content = r#"
pub mod smartbugs {
    use std::path::{Path, PathBuf};
    use std::fs;
    use std::collections::HashMap;
    use std::io::{self, Read};
    
    pub struct SmartBugsDataset {
        base_path: PathBuf,
        categories: Vec<String>,
        contract_map: HashMap<String, Vec<PathBuf>>,
    }
    
    impl SmartBugsDataset {
        pub fn new(base_path: &Path) -> io::Result<Self> {
            let mut dataset = SmartBugsDataset {
                base_path: base_path.to_path_buf(),
                categories: Vec::new(),
                contract_map: HashMap::new(),
            };
            
            dataset.load()?;
            Ok(dataset)
        }
        
        fn load(&mut self) -> io::Result<()> {
            // Find all category directories
            for entry in fs::read_dir(&self.base_path)? {
                let entry = entry?;
                let path = entry.path();
                
                if path.is_dir() && path.file_name().is_some() {
                    let category = path.file_name().unwrap().to_string_lossy().to_string();
                    if category != "processed" { // Skip special directories
                        self.categories.push(category.clone());
                        let mut contract_paths = Vec::new();
                        
                        // Find all contracts in this category
                        for contract in fs::read_dir(path)? {
                            let contract = contract?;
                            let contract_path = contract.path();
                            if contract_path.is_file() && contract_path.extension().map_or(false, |ext| ext == "sol") {
                                contract_paths.push(contract_path);
                            }
                        }
                        
                        self.contract_map.insert(category, contract_paths);
                    }
                }
            }
            
            Ok(())
        }
        
        pub fn get_categories(&self) -> &[String] {
            &self.categories
        }
        
        pub fn get_contracts_for_category(&self, category: &str) -> Option<&[PathBuf]> {
            self.contract_map.get(category).map(|v| v.as_slice())
        }
        
        pub fn get_contract_content(&self, path: &Path) -> io::Result<String> {
            let mut file = fs::File::open(path)?;
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            Ok(content)
        }
        
        // Function to get bytecode - you would implement this to use solc
        pub fn get_bytecode(&self, path: &Path) -> io::Result<Vec<u8>> {
            // Placeholder - in reality you would compile the Solidity file
            // and return the bytecode
            let content = self.get_contract_content(path)?;
            Ok(content.into_bytes())
        }
    }
}
"#;
    
    fs::write(lib_rs_path, lib_content)?;
    
    // Create a simple Cargo.toml file
    let cargo_toml_path = base_dir.join("Cargo.toml");
    let cargo_content = r#"
[package]
name = "evm-verify-datasets"
version = "0.1.0"
edition = "2021"

[dependencies]
"#;

    fs::write(cargo_toml_path, cargo_content)?;
    
    Ok(())
}
