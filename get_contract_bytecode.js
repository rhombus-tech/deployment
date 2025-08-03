// Script to fetch contract bytecode and analyze it
const { ethers } = require('ethers');

async function main() {
  // Contract address of the Trader Joe Router
  const contractAddress = '0x60aE616a2155Ee3d9A68541Ba4544862310933d4';
  
  // Connect to an Avalanche C-Chain RPC endpoint
  const provider = new ethers.JsonRpcProvider('https://api.avax.network/ext/bc/C/rpc');
  
  try {
    console.log(`Fetching bytecode for ${contractAddress}...`);
    
    // Get runtime bytecode
    const runtimeBytecode = await provider.getCode(contractAddress);
    console.log(`\nRuntime Bytecode (${runtimeBytecode.length / 2 - 1} bytes):`);
    console.log(runtimeBytecode);
    
    // Basic analysis
    console.log('\nBasic Analysis:');
    
    // Look for DELEGATECALL opcode (0xf4)
    const delegateCallCount = countOccurrences(runtimeBytecode, '0xf4');
    console.log(`DELEGATECALL opcodes: ${delegateCallCount}`);
    
    // Look for SSTORE opcode (0x55)
    const sstoreCount = countOccurrences(runtimeBytecode, '0x55');
    console.log(`SSTORE opcodes: ${sstoreCount}`);
    
    // Check for slippage related constants 
    // (This is simplified - actual analysis would be more sophisticated)
    const hasSlippagePattern = runtimeBytecode.includes('736c6970706167655f70726f74656374696f6e'); // "slippage_protection" in hex
    console.log(`Has slippage protection pattern: ${hasSlippagePattern}`);
    
  } catch (error) {
    console.error('Error fetching bytecode:', error);
  }
}

// Helper function to count occurrences of an opcode
function countOccurrences(bytecode, opcode) {
  let count = 0;
  let position = 0;
  
  while(true) {
    position = bytecode.indexOf(opcode, position);
    if (position === -1) break;
    count++;
    position += opcode.length;
  }
  
  return count;
}

main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
