// Netlify serverless function to proxy proving service requests

const https = require('https');
const url = require('url');

function makeRequest(targetUrl) {
    return new Promise((resolve, reject) => {
        const options = url.parse(targetUrl);
        options.headers = {
            'User-Agent': 'curl/7.68.0',
            'Accept': '*/*',
            'Bypass-Tunnel-Reminder': 'true'
        };
        
        const req = https.get(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                console.log('Response status:', res.statusCode);
                console.log('Response headers:', JSON.stringify(res.headers, null, 2));
                console.log('Raw response length:', data.length);
                console.log('Raw response (first 500 chars):', data.substring(0, 500));
                
                if (res.statusCode === 200) {
                    try {
                        const jsonData = JSON.parse(data);
                        console.log('Successfully parsed JSON:', JSON.stringify(jsonData));
                        resolve(jsonData);
                    } catch (parseError) {
                        console.error('JSON parse error:', parseError.message);
                        console.log('Full response that failed to parse:', data);
                        reject(new Error(`Invalid JSON response: ${data.substring(0, 200)}...`));
                    }
                } else {
                    console.error('Non-200 status code received');
                    reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
                }
            });
        });
        
        req.on('error', (error) => {
            console.error('Request error:', error);
            reject(error);
        });
        
        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

exports.handler = async (event, context) => {
    const { path, httpMethod } = event;
    
    // Handle CORS for OPTIONS requests
    if (httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            },
            body: '',
        };
    }
    
    try {
        // Extract the path after /api/proxy/
        const targetPath = path.replace('/.netlify/functions/proxy', '') || '/status';
        
        // Forward requests to the localtunnel URL
        const tunnelUrl = 'https://zk-evm.org';
        const targetUrl = `${tunnelUrl}${targetPath}`;
        
        console.log('Forwarding request to:', targetUrl);
        
        const data = await makeRequest(targetUrl);
        console.log('Successfully fetched live data from tunnel');
        
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        };
        
    } catch (error) {
        console.error('Proxy error:', error);
        
        // Return fallback mock data with error indication
        const mockData = {
            average_proving_time: 32.4,
            tps: 9200,
            latest_block: 19234567,
            blocks_proven: 100,
            total_transactions: 4567891,
            proof_generation_rate: 120.5,
            memory_usage_mb: 256.8,
            cpu_utilization: 78.2,
            active_threads: 8,
            queue_size: 12,
            success_rate: 99.97,
            uptime_seconds: 86432,
            last_update: new Date().toISOString(),
            _fallback: true,
            _error: error.message
        };
        
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(mockData),
        };
    }
};
