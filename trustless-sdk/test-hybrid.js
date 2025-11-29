/**
 * Test Hybrid Proving Model
 * Shows all 3 deployment options
 */

const { Trustless } = require('./dist/index.js');

async function testHybrid() {
  console.log('═══════════════════════════════════════════════════════════');
  console.log('🎯 Testing Hybrid Proving Model');
  console.log('═══════════════════════════════════════════════════════════\n');

  const transaction = {
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    data: '0x',
    value: '1000000000000000',
    gasLimit: '21000'
  };

  // ============================================================================
  // MODE 1: Server-Side Proving (Hosted or Local)
  // ============================================================================
  console.log('🔹 MODE 1: Server-Side Proving');
  console.log('─────────────────────────────────────');
  console.log('Use case: Production with your hosted prover');
  console.log('          OR user runs local prover\n');
  
  try {
    await Trustless.init({ 
      provingServer: 'http://localhost:3000',  // Your server OR localhost:3000
      debug: true
    });
    
    console.log('Generating proof via server...');
    const proof1 = await Trustless.prove(transaction);
    console.log('✅ Proof generated!');
    console.log(`   Trustless Score: ${proof1.trustlessScore}/100`);
    console.log(`   Proving Time: ${proof1.zkProof.provingTime}ms`);
    console.log(`   Mode: Full ZODA (server-side)\n`);
  } catch (error) {
    console.log('⚠️  Server not available:', error.message, '\n');
  }

  // ============================================================================
  // MODE 2: WASM-Only (Offline)
  // ============================================================================
  console.log('🔹 MODE 2: WASM-Only (No Server)');
  console.log('─────────────────────────────────────');
  console.log('Use case: Offline mode, no server required\n');
  
  try {
    await Trustless.init({ 
      // No provingServer = WASM only
      debug: true
    });
    
    console.log('Generating proof via WASM...');
    const proof2 = await Trustless.prove(transaction);
    console.log('✅ Proof generated!');
    console.log(`   Trustless Score: ${proof2.trustlessScore}/100`);
    console.log(`   Proving Time: ${proof2.zkProof.provingTime}ms`);
    console.log(`   Mode: Lightweight (WASM)\n`);
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // ============================================================================
  // MODE 3: Hybrid (Best of Both)
  // ============================================================================
  console.log('🔹 MODE 3: Hybrid (Recommended)');
  console.log('─────────────────────────────────────');
  console.log('Use case: Try server, fallback to WASM\n');
  
  try {
    await Trustless.init({ 
      provingServer: 'http://localhost:3000',
      fallbackToWasm: true,  // ← This enables hybrid mode
      debug: true
    });
    
    console.log('Generating proof (hybrid mode)...');
    const proof3 = await Trustless.prove(transaction);
    console.log('✅ Proof generated!');
    console.log(`   Trustless Score: ${proof3.trustlessScore}/100`);
    console.log(`   Proving Time: ${proof3.zkProof.provingTime}ms\n`);
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // ============================================================================
  // Summary
  // ============================================================================
  console.log('═══════════════════════════════════════════════════════════');
  console.log('📊 DEPLOYMENT OPTIONS SUMMARY');
  console.log('═══════════════════════════════════════════════════════════\n');
  
  console.log('1️⃣  SERVER-ONLY:');
  console.log('   { provingServer: "https://prover.yourapp.com" }');
  console.log('   ✅ Full ZODA power');
  console.log('   ✅ Fast proving (30-46µs)');
  console.log('   ⚠️  Requires server\n');
  
  console.log('2️⃣  WASM-ONLY:');
  console.log('   { } // No provingServer');
  console.log('   ✅ Works offline');
  console.log('   ✅ No infrastructure');
  console.log('   ⚠️  Lightweight proving\n');
  
  console.log('3️⃣  HYBRID (RECOMMENDED):');
  console.log('   { provingServer: "...", fallbackToWasm: true }');
  console.log('   ✅ Best of both worlds');
  console.log('   ✅ Graceful degradation');
  console.log('   ✅ Works offline\n');
  
  console.log('💡 Like Infura: You provide servers, users can run their own');
  console.log('═══════════════════════════════════════════════════════════\n');
}

testHybrid().catch(console.error);
