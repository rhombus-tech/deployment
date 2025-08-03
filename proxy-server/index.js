const express = require('express');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Enable CORS for all routes
app.use(cors());

// Simple proxy endpoint
app.get('/status', async (req, res) => {
    try {
        const response = await fetch('https://zk-evm.org/status', {
            method: 'GET',
            headers: {
                'Bypass-Tunnel-Reminder': 'true',
                'Accept': 'application/json'
            }
        });

        if (response.ok) {
            const data = await response.json();
            res.json(data);
        } else {
            res.status(response.status).json({ error: 'Failed to fetch from tunnel' });
        }
    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Proxy server running on port ${port}`);
});
