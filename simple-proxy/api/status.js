export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    try {
        // Fetch from tunnel with bypass header
        const response = await fetch('https://zk-evm.org/status', {
            method: 'GET',
            headers: {
                'Bypass-Tunnel-Reminder': 'true',
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            return res.status(200).json(data);
        } else {
            return res.status(response.status).json({ 
                error: 'Tunnel request failed', 
                status: response.status 
            });
        }
    } catch (error) {
        console.error('Proxy error:', error);
        return res.status(500).json({ 
            error: 'Proxy failed', 
            message: error.message 
        });
    }
}
