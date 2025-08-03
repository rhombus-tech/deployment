const express = require('express');
const https = require('https');
const app = express();

// Enable CORS for all requests
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        res.sendStatus(200);
    } else {
        next();
    }
});

app.get('/status', (req, res) => {
    console.log('Proxying request to tunnel...');
    
    const options = {
        hostname: 'zk-evm.org',
        port: 443,
        path: '/status',
        method: 'GET',
        headers: {
            'Bypass-Tunnel-Reminder': 'true',
            'Accept': 'application/json'
        }
    };

    const proxyReq = https.request(options, (proxyRes) => {
        let data = '';
        
        proxyRes.on('data', (chunk) => {
            data += chunk;
        });
        
        proxyRes.on('end', () => {
            console.log('Tunnel response:', data);
            res.status(proxyRes.statusCode);
            res.set(proxyRes.headers);
            res.send(data);
        });
    });

    proxyReq.on('error', (err) => {
        console.error('Proxy error:', err);
        res.status(500).json({ error: 'Proxy failed', message: err.message });
    });

    proxyReq.end();
});

app.get('/', (req, res) => {
    res.send('zkEVM Proxy Server is running!');
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Proxy server running on port ${port}`);
});
