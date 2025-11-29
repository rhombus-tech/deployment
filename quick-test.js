// Quick test of hybrid system
const { Trustless } = require('./trustless-sdk/dist/index.js');

(async () => {
  console.log('🧪 Quick Hybrid Test\n');
  
  // Test with server
  console.log('1. Testing with server...');
  await Trustless.init({ 
    provingServer: 'http://localhost:3000',
    fallbackToWasm: true,
    debug: false
  });
  
  const proof = await Trustless.prove({
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    data: '0x',
    value: '1000000000000000',
    gasLimit: '21000'
  });
  
  console.log('✅ Proof generated!');
  console.log(`   Score: ${proof.trustlessScore}/100`);
  console.log(`   Time: ${proof.zkProof.provingTime}ms`);
  console.log('\n🎉 Hybrid system working!\n');
})();
