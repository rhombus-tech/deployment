/**
 * Quick Test Script for Trustless SDK
 */

const { Trustless } = require('./dist/index.js');

async function test() {
  console.log('🧪 Testing Trustless SDK\n');

  try {
    // Test 1: Initialize
    console.log('1️⃣  Testing initialization...');
    console.log('   Calling Trustless.init()...');
    // Initialize without network connection (offline mode)
    await Trustless.init({ 
      enableSecurity: true,
      debug: true
      // No network/rpcUrl = offline mode, no provider needed
    });
    console.log('✅ Initialized successfully\n');

    // Test 2: Prove a transaction
    console.log('2️⃣  Testing prove...');
    const transaction = {
      to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
      data: '0x',
      value: 1000000000000000n,
    };

    const proof = await Trustless.prove(transaction);
    console.log('✅ Proof generated!');
    console.log(`   Trustless Score: ${proof.trustlessScore}/100`);
    console.log(`   Security: ${proof.security.isSecure ? '✅ Secure' : '⚠️  Issues'}`);
    console.log(`   Proof Size: ${proof.zkProof.proof.length} bytes`);
    console.log(`   Proving Time: ${proof.zkProof.provingTime}ms\n`);

    // Test 3: Security verification
    console.log('3️⃣  Testing security verification...');
    const security = await Trustless.verifySecurity(transaction);
    console.log('✅ Security verified!');
    console.log(`   Security Score: ${security.securityScore}/100`);
    console.log(`   Vulnerabilities: ${security.vulnerabilities.length}\n`);

    // Test 4: Atomic bundle
    console.log('4️⃣  Testing atomic bundle...');
    const atomicProof = await Trustless.atomic({
      transactions: [
        { to: '0x123...', data: '0x' },
        { to: '0x456...', data: '0x' },
      ],
    });
    console.log('✅ Atomic proof generated!');
    console.log(`   Guaranteed Atomic: ${atomicProof.guaranteedAtomic}`);
    console.log(`   Bundle Proofs: ${atomicProof.proofs.length}\n`);

    // Test 5: Statistics
    console.log('5️⃣  Testing statistics...');
    const stats = Trustless.getStats();
    console.log('✅ Statistics retrieved!');
    console.log(`   Total Proofs: ${stats.totalProofs}`);
    console.log(`   Successful: ${stats.successfulProofs}`);
    console.log(`   Avg Time: ${stats.averageProvingTime.toFixed(2)}ms\n`);

    console.log('🎉 All tests passed!\n');
    console.log('📝 Note: Currently using mock WASM implementation.');
    console.log('💡 Run "npm run build:wasm" to use the real WASM module.\n');

    // Cleanup
    await Trustless.cleanup();

  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

test();
