const https = require('https');

// Free Ethereum mainnet RPC endpoints
const RPC_ENDPOINTS = [
    'https://eth.llamarpc.com',
    'https://rpc.ankr.com/eth',
    'https://ethereum-rpc.publicnode.com',
    'https://1rpc.io/eth'
];

// Contract addresses to fetch
const CONTRACTS = {
    'CompoundComptroller': '0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3b',
    'CompoundOracle': '0x6d903f6003cca6255D85fcdCdD4820C4213c74Ff',
    'CompoundGovernor': '0xc0Da02939E1441F497fd74F78cE7Decb17B66529'
};

async function fetchBytecode(address, contractName, rpcUrl) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            "jsonrpc": "2.0",
            "method": "eth_getCode",
            "params": [address, "latest"],
            "id": 1
        });

        const url = new URL(rpcUrl);
        const options = {
            hostname: url.hostname,
            port: url.port || 443,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.error) {
                        reject(new Error(`RPC Error: ${response.error.message}`));
                        return;
                    }
                    console.log(`\n📄 ${contractName} (${address}):`);
                    console.log(`   Bytecode length: ${response.result.length - 2} bytes`);
                    console.log(`   First 100 chars: ${response.result.substring(0, 102)}...`);
                    resolve({
                        contractName,
                        address,
                        bytecode: response.result
                    });
                } catch (error) {
                    reject(error);
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.write(postData);
        req.end();
    });
}

async function fetchAllContracts() {
    console.log('🔍 Fetching contract bytecode from Ethereum mainnet...\n');

    const results = [];
    
    for (const [contractName, address] of Object.entries(CONTRACTS)) {
        let success = false;
        
        for (const rpcUrl of RPC_ENDPOINTS) {
            try {
                console.log(`   Trying ${rpcUrl}...`);
                const result = await fetchBytecode(address, contractName, rpcUrl);
                results.push(result);
                success = true;
                break;
            } catch (error) {
                console.log(`   ❌ Failed: ${error.message}`);
                continue;
            }
        }
        
        if (!success) {
            console.log(`   ⚠️  Failed to fetch ${contractName} from all endpoints`);
        }
    }

    console.log('\n🎯 RESULTS:');
    console.log('===============================================');
    
    for (const result of results) {
        console.log(`\n"${result.address}" => {`);
        console.log(`    Ok(hex::decode("${result.bytecode.substring(2)}")?)`);
        console.log(`},`);
    }

    return results;
}

fetchAllContracts().catch(console.error);
