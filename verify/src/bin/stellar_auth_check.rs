// Simple check for Stellar Auth Safety compilation
use verify::circuits::stellar_auth_safety::*;
use walrus::Module;

fn main() {
    println!("Checking Stellar Auth Safety compilation...");
    
    // Create a test module
    let module = Module::default();
    
    // Analyze it
    let vulnerabilities = analyze_stellar_auth_vulnerabilities(&module);
    
    println!("Found {} vulnerabilities", vulnerabilities.len());
}
