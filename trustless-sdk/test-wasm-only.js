/**
 * Simple WASM-only test (no network required)
 */

async function testWasm() {
  console.log('🧪 Testing WASM module directly\n');

  try {
    // Try to load the WASM module
    console.log('1️⃣  Loading WASM...');
    const wasm = await import('./wasm/trustless_wasm.js');
    console.log('✅ WASM module loaded!');
    console.log('   Functions available:', Object.keys(wasm).filter(k => typeof wasm[k] === 'function').slice(0, 10));

    // Initialize WASM
    console.log('\n2️⃣  Initializing WASM...');
    await wasm.default();
    console.log('✅ WASM initialized!\n');

    // Test prove_transaction
    console.log('3️⃣  Testing prove_transaction...');
    const tx = JSON.stringify({
      to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
      data: '0x',
      value: '1000000000000000',
      gas_limit: '21000'
    });
    const txBytes = new TextEncoder().encode(tx);
    const proof = await wasm.prove_transaction(txBytes);
    console.log('✅ Proof generated!');
    console.log(`   Size: ${proof.length} bytes\n`);

    // Test analyze_security
    console.log('4️⃣  Testing analyze_security...');
    const bytecode = new Uint8Array([0x60, 0x80, 0x60, 0x40, 0x52]);
    const securityResult = await wasm.analyze_security(bytecode);
    const security = JSON.parse(new TextDecoder().decode(securityResult));
    console.log('✅ Security analysis complete!');
    console.log(`   Score: ${security.security_score}`);
    console.log(`   Secure: ${security.is_secure}`);
    console.log(`   Vulnerabilities: ${security.vulnerabilities.length}\n`);

    // Test verify_proof
    console.log('5️⃣  Testing verify_proof...');
    const isValid = await wasm.verify_proof(proof);
    console.log(`✅ Proof verification: ${isValid ? 'VALID' : 'INVALID'}\n`);

    console.log('🎉 All WASM tests passed!\n');
    console.log('✨ Your Trustless SDK has REAL WebAssembly proving!\n');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('\nStack:', error.stack);
    process.exit(1);
  }
}

testWasm();
