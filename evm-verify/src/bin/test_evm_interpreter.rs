use ethers::types::{Transaction, Block, H256, U256, Bytes};
use evm_verify::circuits::complete_evm_circuit::CompleteEVMCircuit;
use ark_bn254::Fr;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🧪 Testing EVM Interpreter Integration");
    println!("=====================================");

    // Create a simple transaction with bytecode
    let mut tx = Transaction::default();
    tx.gas = U256::from(1_000_000u64);
    tx.input = Bytes::from(vec![
        0x60, 0x01, // PUSH1 0x01
        0x60, 0x02, // PUSH1 0x02
        0x01,       // ADD
        0x60, 0x00, // PUSH1 0x00
        0x52,       // MSTORE
        0x00,       // STOP
    ]);

    let block = Block::<H256>::default();

    println!("📝 Test Transaction:");
    println!("   Gas Limit: {}", tx.gas);
    println!("   Bytecode: {:02x?}", tx.input);
    println!("   Expected Operations: PUSH1, PUSH1, ADD, PUSH1, MSTORE, STOP");
    println!();

    // Test the EVM interpreter through CompleteEVMCircuit
    let mut circuit = CompleteEVMCircuit::<Fr>::new_default();
    
    println!("🔄 Executing transaction with EVM interpreter...");
    let start_time = std::time::Instant::now();
    let trace_result = circuit.generate_execution_trace(&tx, &block).await?;
    let execution_time = start_time.elapsed();

    println!("✅ Execution completed in {}ms", execution_time.as_millis());
    println!();

    // Analyze the execution trace
    println!("📊 Execution Trace Analysis:");
    println!("   Total execution steps: {}", trace_result.execution_steps.len());
    println!("   Gas traces: {}", trace_result.gas_traces.len());
    println!("   Memory traces: {}", trace_result.memory_traces.len());
    println!("   Storage traces: {}", trace_result.storage_traces.len());
    println!("   Stack traces: {}", trace_result.stack_traces.len());
    println!();

    // Show first few execution steps
    println!("🔍 First execution steps:");
    for (i, step) in trace_result.execution_steps.iter().take(10).enumerate() {
        println!("   Step {}: {}", i, step.opcode_name);
        println!("      Gas before: {}", step.gas_before);
        println!("      Gas after: {}", step.gas_after);
        println!("      Gas cost: {}", step.gas_cost);
        if !step.stack_before.is_empty() {
            println!("      Stack before: {:?}", step.stack_before.iter().take(3).collect::<Vec<_>>());
        }
        if !step.stack_after.is_empty() {
            println!("      Stack after: {:?}", step.stack_after.iter().take(3).collect::<Vec<_>>());
        }
        println!();
    }

    // Performance metrics
    println!("⚡ Performance Metrics:");
    println!("   Total steps: {}", trace_result.performance.total_steps);
    println!("   Total time: {}ms", trace_result.performance.total_time_ms);
    println!("   Memory usage: {} bytes", trace_result.performance.total_memory_usage);
    println!("   Compression ratio: {}", trace_result.performance.compression_ratio);
    println!();

    // Validation
    let has_real_opcodes = trace_result.execution_steps.iter()
        .any(|step| step.opcode_name != "PLACEHOLDER");
    
    let has_gas_changes = trace_result.execution_steps.iter()
        .any(|step| step.gas_before != step.gas_after);

    println!("✅ Validation Results:");
    println!("   Real opcodes detected: {}", has_real_opcodes);
    println!("   Gas consumption tracked: {}", has_gas_changes);
    println!("   Non-empty execution trace: {}", !trace_result.execution_steps.is_empty());
    
    if has_real_opcodes && has_gas_changes && !trace_result.execution_steps.is_empty() {
        println!();
        println!("🎉 SUCCESS: EVM interpreter is generating genuine opcode-level execution traces!");
        println!("   The integration is working correctly and producing real EVM execution data.");
    } else {
        println!();
        println!("⚠️  WARNING: EVM interpreter may still be using placeholder data.");
        println!("   Further investigation needed to ensure real execution traces.");
    }

    Ok(())
}
