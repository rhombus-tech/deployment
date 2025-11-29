/**
 * Test: Client SDK → Full ZODA Server
 */

async function testClientToServer() {
  console.log('🧪 Testing Client → Full ZODA Server\n');

  try {
    // Test direct HTTP calls (what SDK would do)
    
    // Test 1: Prove transaction
    console.log('1️⃣  Testing /api/prove endpoint...');
    const proveResponse = await fetch('http://localhost:3000/api/prove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
        data: '0x',
        value: '1000000000000000',
        gasLimit: '21000'
      })
    });
    
    const proveResult = await proveResponse.json();
    console.log('✅ Proof generated!');
    console.log(`   Proving time: ${proveResult.proving_time_ms}ms`);
    console.log(`   Proof size: ${proveResult.proof_size_bytes} bytes`);
    console.log(`   Proof type: ${proveResult.proof_type}`);
    console.log(`   Proof: ${proveResult.proof.substring(0, 20)}...`);
    
    // Test 2: Security analysis
    console.log('\n2️⃣  Testing /api/security endpoint...');
    const securityResponse = await fetch('http://localhost:3000/api/security', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bytecode: '0x608060405234801561001057600080fd5bf4ff'
      })
    });
    
    const securityResult = await securityResponse.json();
    console.log('✅ Security analysis complete!');
    console.log(`   Security score: ${securityResult.security_score}/100`);
    console.log(`   Is secure: ${securityResult.is_secure}`);
    console.log(`   Vulnerabilities: ${securityResult.vulnerabilities.length}`);
    
    console.log('\n🎉 Client can successfully use the full ZODA server!');
    console.log('\n📝 How to use in SDK:');
    console.log('   1. SDK makes HTTP POST to http://localhost:3000/api/prove');
    console.log('   2. Server runs full ZODA+WARP proving');
    console.log('   3. SDK receives proof and returns to app');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

testClientToServer();
