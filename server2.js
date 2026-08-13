const express = require('express');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync('links.json');
const db = low(adapter);

// Initialize JSON database schema
db.defaults({ links: [] }).write();

const app = express();
const PORT = 3000;

// Trust Cloudflare / Proxy headers
app.set('trust proxy', true);

// CONFIGURATION: Set your dashboard access password here
const DASHBOARD_PASSWORD = 'Param@Army21'; 
const HASHED_PASSWORD = bcrypt.hashSync(DASHBOARD_PASSWORD, 10);

console.log('Connected to JSON database links.json');

app.use(express.urlencoded({ extended: true }));

// 1. FRONTEND DASHBOARD
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Link Manager</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; line-height: 1.6; background-color: #f9f9f9;}
                .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                input { width: 100%; padding: 12px; margin: 10px 0 20px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
                button { background: #007BFF; color: white; border: none; padding: 12px; cursor: pointer; width: 100%; font-size: 16px; border-radius: 4px; font-weight: bold; }
                button:hover { background: #0056b3; }
                h2 { color: #333; margin-top: 0; }
                label { font-weight: bold; color: #555; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>Secure Link Generator</h2>
                <form action="/create" method="POST">
                    <label>Dashboard Password:</label>
                    <input type="password" name="password" placeholder="Enter security password" required />
                    
                    <label>Target Destination URL:</label>
                    <input type="text" name="originalUrl" placeholder="https://youtube.com..." required />
                    
                    <button type="submit">Generate Secure Tracking Link</button>
                </form>
            </div>
        </body>
        </html>
    `);
});

// 2. PASSWORD VERIFICATION & LINK SAVING
app.post('/create', (req, res) => {
    const inputPassword = req.body.password || '';
    let originalUrl = (req.body.originalUrl || '').trim();

    const isPasswordValid = bcrypt.compareSync(inputPassword, HASHED_PASSWORD);

    if (!isPasswordValid) {
        return res.status(403).send(`
            <h3 style="color:red; text-align:center; font-family:Arial;">Access Denied: Incorrect Password</h3>
            <p style="text-align:center;"><a href="/">Try Again</a></p>
        `);
    }

    if (!/^https?:\/\//i.test(originalUrl)) {
        originalUrl = 'https://' + originalUrl;
    }

    const uniqueId = crypto.randomBytes(3).toString('hex');

    try {
        db.get('links').push({ id: uniqueId, original_url: originalUrl }).write();

        // Detect if protocol is https (Cloudflare) or http
        const protocol = req.headers['x-forwarded-proto'] || req.protocol;
        const host = req.get('host');
        const modifiedLink = `${protocol}://${host}/t/${uniqueId}`;

        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Secure Link Generated</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; text-align: center;}
                    .box { background: #e3f2fd; padding: 20px; border: 1px solid #90caf9; word-break: break-all; margin-bottom: 20px; border-radius: 4px;}
                    a { color: #007BFF; font-weight: bold; text-decoration: none;}
                </style>
            </head>
            <body>
                <h2>Secure Link Generated!</h2>
                <div class="box">
                    <p>Share this link to monitor incoming connections:</p>
                    <p><a href="${modifiedLink}" target="_blank">${modifiedLink}</a></p>
                </div>
                <p><a href="/">← Go Back to Dashboard</a></p>
            </body>
            </html>
        `);
    } catch (err) {
        console.error('Database write error:', err.message);
        return res.status(500).send('Database tracking setup failed.');
    }
});

// 3. TRACKING AND AUTOMATIC REDIRECTION
app.get('/t/:id', async (req, res) => {
    const id = req.params.id;

    try {
        const record = db.get('links').find({ id }).value();

        if (!record) {
            return res.status(404).send('Resource unavailable or invalid link parameter.');
        }

        const targetUrl = record.original_url;

        // Extract client IP address from Cloudflare header or socket
        let rawIp = req.headers['cf-connecting-ip'] || 
                    req.headers['x-forwarded-for'] || 
                    req.socket.remoteAddress || '';
        
        if (rawIp.includes(',')) {
            rawIp = rawIp.split(',')[0].trim();
        }

        if (rawIp.startsWith('::ffff:')) {
            rawIp = rawIp.replace('::ffff:', '');
        }

        // If local testing without Cloudflare
        if (rawIp === '::1' || rawIp === '127.0.0.1') {
            rawIp = '8.8.8.8'; 
        }

        const userAgent = req.headers['user-agent'] || 'Unknown Browser Signature';
        let geoData = { country: 'Unknown', region: 'Unknown', city: 'Unknown', isp: 'Unknown' };

        // Fetch Geolocation data
        try {
            const response = await axios.get(`http://ip-api.com/json/${rawIp}`, {
                headers: { 'User-Agent': 'Mozilla/5.0' },
                timeout: 3000
            });
            if (response.data && response.data.status === 'success') {
                geoData = {
                    country: response.data.country || 'Unknown',
                    region: response.data.regionName || 'Unknown',
                    city: response.data.city || 'Unknown',
                    isp: response.data.isp || 'Unknown'
                };
            }
        } catch (error) {
            console.error('Geolocation lookup failed:', error.message);
        }

        const timestamp = new Date().toISOString();
        const logString = `[${timestamp}] ID: ${id} | Dest: ${targetUrl} | IP: ${rawIp} | Geo: ${geoData.city}, ${geoData.region}, ${geoData.country} | ISP: ${geoData.isp} | Browser: ${userAgent}\n`;

        fs.appendFile('ip_log.txt', logString, (err) => {
            if (err) console.error('Disk logging failure:', err);
        });

        // Instant redirect
        res.redirect(targetUrl);

    } catch (err) {
        console.error('Database read error:', err.message);
        res.status(500).send('Server error processing request.');
    }
});

app.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`Server fully operational on http://localhost:${PORT}`);
    console.log(`=================================================\n`);
});

