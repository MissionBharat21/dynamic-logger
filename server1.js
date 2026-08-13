const express = require('express');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;

// CONFIGURATION: Set your dashboard access password here
const DASHBOARD_PASSWORD = 'MySecretPassword123'; 
// Generate a pre-hashed version for secure comparison
const HASHED_PASSWORD = bcrypt.hashSync(DASHBOARD_PASSWORD, 10);

// Initialize SQLite database file with better-sqlite3
const db = new Database('./links.db');
console.log('Connected to permanent database links.db');

// Create tables for links
db.exec(`CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    original_url TEXT
)`);

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

    // Verify password against the secure hash
    const isPasswordValid = bcrypt.compareSync(inputPassword, HASHED_PASSWORD);

    if (!isPasswordValid) {
        return res.status(403).send(`
            <h3 style="color:red; text-align:center; font-family:Arial;">Access Denied: Incorrect Password</h3>
            <p style="text-align:center;"><a href="/">Try Again</a></p>
        `);
    }

    // Ensure URL has http:// or https:// protocol
    if (!/^https?:\/\//i.test(originalUrl)) {
        originalUrl = 'https://' + originalUrl;
    }

    const uniqueId = crypto.randomBytes(3).toString('hex'); // Generate 6-character hex ID

    try {
        // Synchronous insert using better-sqlite3
        const stmt = db.prepare('INSERT INTO links (id, original_url) VALUES (?, ?)');
        stmt.run(uniqueId, originalUrl);

        const host = req.get('host');
        const protocol = req.protocol;
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
        // Synchronous query using better-sqlite3
        const stmt = db.prepare('SELECT original_url FROM links WHERE id = ?');
        const row = stmt.get(id);

        if (!row) {
            return res.status(404).send('Resource unavailable or invalid link parameter.');
        }

        const targetUrl = row.original_url;

        // Extract client IP address properly
        let rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
        
        if (rawIp.includes(',')) {
            rawIp = rawIp.split(',')[0].trim();
        }

        if (rawIp === '::1' || rawIp === '127.0.0.1') {
            rawIp = '8.8.8.8'; // Mock IP for local testing
        } else if (rawIp.startsWith('::ffff:')) {
            rawIp = rawIp.replace('::ffff:', '');
        }

        const userAgent = req.headers['user-agent'] || 'Unknown Browser Signature';
        let geoData = { country: 'Unknown', region: 'Unknown', city: 'Unknown', isp: 'Unknown' };

        // Fetch location details from public geolocation API
        try {
            const response = await axios.get(`http://ip-api.com/json/${rawIp}`);
            if (response.data && response.data.status === 'success') {
                geoData = {
                    country: response.data.country || 'Unknown',
                    region: response.data.regionName || 'Unknown',
                    city: response.data.city || 'Unknown',
                    isp: response.data.isp || 'Unknown'
                };
            }
        } catch (error) {
            console.error('Network geolocation registry unreachable:', error.message);
        }

        // Log client metrics
        const timestamp = new Date().toISOString();
        const logString = `[${timestamp}] ID: ${id} | Dest: ${targetUrl} | IP: ${rawIp} | Geo: ${geoData.city}, ${geoData.region}, ${geoData.country} | ISP: ${geoData.isp} | Browser: ${userAgent}\n`;

        fs.appendFile('ip_log.txt', logString, (err) => {
            if (err) console.error('Disk logging failure:', err);
        });

        // Redirect to original link
        res.redirect(targetUrl);

    } catch (err) {
        console.error('Database read error:', err.message);
        res.status(500).send('Server error processing request.');
    }
});

app.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`Server fully operational on http://localhost:${PORT}`);
    console.log(`Security Notice: Only requests with valid passwords will generate links.`);
    console.log(`=================================================\n`);
});

