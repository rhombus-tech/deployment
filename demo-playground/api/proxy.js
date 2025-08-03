// Vercel serverless function to proxy proving service requests

export default async function handler(req, res) {
    // Handle CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    try {
        // Extract the target path
        const targetPath = req.url.replace('/api/proxy', '') || '/status';
        
        // Forward requests to the localtunnel URL
        const tunnelUrl = 'https://zk-evm.org';
        const targetUrl = `${tunnelUrl}${targetPath}`;
        
        console.log('Forwarding request to:', targetUrl);
        
        const response = await fetch(targetUrl, {
            method: req.method,
            headers: {
                'User-Agent': 'curl/7.68.0',
                'Accept': '*/*',
                'Bypass-Tunnel-Reminder': 'true'
            }
        });
        
        console.log('Response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Successfully fetched live data from tunnel');
            
            res.status(200).json(data);
        } else {
            const errorText = await response.text();
            console.error('Tunnel response not OK:', response.status, response.statusText);
            console.error('Error response body:', errorText);
            throw new Error(`Tunnel returned ${response.status}: ${response.statusText}`);
        }
        
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
        
        res.status(200).json(mockData);
    }
}
