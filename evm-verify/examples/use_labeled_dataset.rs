use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::error::Error;

// Import the ML structures and functions from the original example
mod ml_models {
    use std::collections::HashMap;
    
    // Features for ML pipeline
    pub type FeatureVector = Vec<f32>;
    pub type Label = u8;

    // ML model representation
    pub struct VulnerabilityModel {
        pub vulnerability_type_str: String,
        pub exploitability_threshold: f32,
    }

    // Simple ML model for predicting exploitability
    pub fn predict_exploitability(features: &FeatureVector, _model: &VulnerabilityModel) -> f32 {
        // In a real implementation, this would use a trained model to make predictions
        // For now, we'll use a simple heuristic based on features
        
        let bytecode_size = features[0];
        let opcode_diversity = features[1];
        let storage_ops = features[2];
        let external_calls = features[3];
        
        // Simple weighted score calculation
        let score = (bytecode_size * 0.01) + (opcode_diversity * 0.2) + 
                    (storage_ops * 0.3) + (external_calls * 0.5);
        
        // Normalize to 0-1 range
        let normalized_score = (score / 1000.0).min(1.0);
        
        normalized_score
    }

    // Create vulnerability detection models
    pub fn create_vulnerability_models() -> HashMap<String, VulnerabilityModel> {
        let mut models = HashMap::new();
        
        // Create models for each vulnerability type
        models.insert("reentrancy".to_string(), VulnerabilityModel {
            vulnerability_type_str: "reentrancy".to_string(),
            exploitability_threshold: 0.7,
        });
        
        models.insert("cross_contract_reentrancy".to_string(), VulnerabilityModel {
            vulnerability_type_str: "cross_contract_reentrancy".to_string(),
            exploitability_threshold: 0.75,
        });
        
        models.insert("integer_overflow".to_string(), VulnerabilityModel {
            vulnerability_type_str: "integer_overflow".to_string(),
            exploitability_threshold: 0.65,
        });
        
        models.insert("integer_underflow".to_string(), VulnerabilityModel {
            vulnerability_type_str: "integer_underflow".to_string(),
            exploitability_threshold: 0.65,
        });
        
        models.insert("precision_loss".to_string(), VulnerabilityModel {
            vulnerability_type_str: "precision_loss".to_string(),
            exploitability_threshold: 0.6,
        });
        
        models.insert("uninitialized_storage".to_string(), VulnerabilityModel {
            vulnerability_type_str: "uninitialized_storage".to_string(),
            exploitability_threshold: 0.8,
        });
        
        models.insert("access_control".to_string(), VulnerabilityModel {
            vulnerability_type_str: "access_control".to_string(),
            exploitability_threshold: 0.75,
        });
        
        models.insert("gas_griefing".to_string(), VulnerabilityModel {
            vulnerability_type_str: "gas_griefing".to_string(),
            exploitability_threshold: 0.7,
        });
        
        models.insert("unchecked_calls".to_string(), VulnerabilityModel {
            vulnerability_type_str: "unchecked_calls".to_string(),
            exploitability_threshold: 0.65,
        });
        
        models
    }
}

// Dataset representation
struct DatasetEntry {
    contract_address: String,
    vulnerability_type: String,
    features: ml_models::FeatureVector,
    label: ml_models::Label,
}

// Load the labeled dataset
fn load_dataset(path: &str) -> Result<Vec<DatasetEntry>, Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut dataset = Vec::new();
    
    // Skip header line
    for line in reader.lines().skip(1) {
        let line = line?;
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() < 10 {
            continue;
        }
        
        let contract_address = parts[0].to_string();
        let vulnerability_type = parts[1].to_string();
        
        // Extract features
        let mut features = Vec::new();
        features.push(parts[2].parse::<f32>()?); // bytecode_size
        features.push(parts[3].parse::<f32>()?); // opcode_diversity
        features.push(parts[4].parse::<f32>()?); // storage_ops
        features.push(parts[5].parse::<f32>()?); // memory_ops
        features.push(parts[6].parse::<f32>()?); // external_calls
        features.push(parts[7].parse::<f32>()?); // jumps
        features.push(parts[8].parse::<f32>()?); // complexity
        
        let label = parts[9].parse::<ml_models::Label>()?;
        
        dataset.push(DatasetEntry {
            contract_address,
            vulnerability_type,
            features,
            label,
        });
    }
    
    Ok(dataset)
}

// Calculate metrics for dataset evaluation
fn calculate_metrics(dataset: &[DatasetEntry], models: &HashMap<String, ml_models::VulnerabilityModel>) {
    let mut tp = 0;
    let mut fp = 0;
    let mut tn = 0;
    let mut fn_count = 0;
    
    for entry in dataset {
        if let Some(model) = models.get(&entry.vulnerability_type) {
            let prediction = ml_models::predict_exploitability(&entry.features, model);
            let predicted_positive = prediction >= model.exploitability_threshold;
            let actual_positive = entry.label == 1;
            
            if predicted_positive && actual_positive {
                tp += 1;
            } else if predicted_positive && !actual_positive {
                fp += 1;
            } else if !predicted_positive && !actual_positive {
                tn += 1;
            } else if !predicted_positive && actual_positive {
                fn_count += 1;
            }
        }
    }
    
    let accuracy = (tp + tn) as f32 / (tp + tn + fp + fn_count) as f32;
    let precision = if tp + fp > 0 { tp as f32 / (tp + fp) as f32 } else { 0.0 };
    let recall = if tp + fn_count > 0 { tp as f32 / (tp + fn_count) as f32 } else { 0.0 };
    let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };
    
    println!("Model Evaluation Metrics:");
    println!("  Accuracy:  {:.4}", accuracy);
    println!("  Precision: {:.4}", precision);
    println!("  Recall:    {:.4}", recall);
    println!("  F1 Score:  {:.4}", f1);
    println!("  True Positives: {}", tp);
    println!("  False Positives: {}", fp);
    println!("  True Negatives: {}", tn);
    println!("  False Negatives: {}", fn_count);
}

// Generate statistics about the vulnerability distribution
fn analyze_vulnerability_distribution(dataset: &[DatasetEntry]) {
    let mut vuln_counts: HashMap<String, (u32, u32)> = HashMap::new(); // (positive, total)
    
    for entry in dataset {
        let (pos, total) = vuln_counts.entry(entry.vulnerability_type.clone()).or_insert((0, 0));
        if entry.label == 1 {
            *pos += 1;
        }
        *total += 1;
    }
    
    println!("Vulnerability Distribution in Dataset:");
    println!("----------------------------------------");
    println!("| Vulnerability Type         | Positive | Total | Rate   |");
    println!("----------------------------------------");
    
    for (vuln_type, (positive, total)) in vuln_counts.iter() {
        let rate = if *total > 0 { *positive as f32 / *total as f32 } else { 0.0 };
        println!("| {:<25} | {:<8} | {:<5} | {:.2}% |", 
                vuln_type.replace("_", " "), positive, total, rate * 100.0);
    }
    println!("----------------------------------------");
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("ML-Enhanced Vulnerability Analysis using Labeled Dataset");
    
    // Path to labeled dataset
    let dataset_path = "datasets/processed/vulnerability_dataset.csv";
    
    // Load the dataset
    let dataset = load_dataset(dataset_path)?;
    println!("Loaded {} dataset entries from {}", dataset.len(), dataset_path);
    
    // Initialize vulnerability detection models
    let models = ml_models::create_vulnerability_models();
    
    // Analyze vulnerability distribution
    analyze_vulnerability_distribution(&dataset);
    
    // Calculate model metrics
    calculate_metrics(&dataset, &models);
    
    // Demonstrate enhanced vulnerability detection with ML
    println!("\nUsing ML to enhance vulnerability detection accuracy...");
    
    // Select a sample contract for demonstration
    if let Some(sample) = dataset.first() {
        println!("Sample contract: {}", sample.contract_address);
        println!("Vulnerability type: {}", sample.vulnerability_type);
        
        if let Some(model) = models.get(&sample.vulnerability_type) {
            let exploitability = ml_models::predict_exploitability(&sample.features, model);
            println!("ML prediction - Exploitability score: {:.4}", exploitability);
            println!("Threshold: {:.4}", model.exploitability_threshold);
            println!("ML verdict: {}", if exploitability >= model.exploitability_threshold { "VULNERABLE" } else { "SAFE" });
            println!("Actual label: {}", if sample.label == 1 { "VULNERABLE" } else { "SAFE" });
        }
    }
    
    println!("\nDataset fetched and ML analysis complete!");
    Ok(())
}
