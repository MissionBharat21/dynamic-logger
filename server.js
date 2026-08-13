const express = require('express');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs'); // For secure password handling
const app = express();
const PORT = 3000;

// CONFIGURATION: Set your dashboard access password here
const DASHBOARD_PASSWORD = 'MySecretPassword123'; 
// Generate a pre-hashed version for secure comparison
const HASHED_PASSWORD = bcrypt.hashSync(DASHBOARD_PASSWORD, 10);

// Initialize SQLite database file
const db = new sqlite3.Database('./links.db', (err) => {
    if (err) console.error('Database opening error:', err.message);
    else console.log('Connected to permanent database links.db');
});

// Create tables for links
db.run(`CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    original_url TEXT
)`);

app.use(express.urlencoded({ extended: true }));

// 1. SECURE FRONTEND DASHBOARD
app.get('/', (req, res) => {
    // Basic interface asking for password and target link on one screen
    res.send(`
        <!DOCTYPE html>
        <html>
q        <head>
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
                    <input type="text" name="originalUrl" placeholder="https://youtube.com... or https://instagram.com..." required />
                    
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
    const originalUrl = req.body.originalUrl;

    // Verify password against the secure hash
    const isPasswordValid = bcrypt.compareSync(inputPassword, HASHED_PASSWORD);

    if (!isPasswordValid) {
        return res.status(403).send(`
            <h3 style="color:red; text-align:center; font-family:Arial;">Access Denied: Incorrect Password</h3>
            <p style="text-align:center;"><a href="/">Try Again</a></p>
        `);
    }

    const uniqueId = crypto.randomBytes(3).toString('hex'); // Generate clean 6-character hex ID

    // Store link permanently into SQLite
    db.run(`INSERT INTO links (id, original_url) VALUES (?, ?)`, [uniqueId, originalUrl], (err) => {
        if (err) {
            console.error('Database write error:', err.message);
            return res.status(500).send('Database tracking setup failed.');
        }

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
                    <p>Share this link to safely monitor incoming connections:</p>
                    <p><a href="${modifiedLink}" target="_blank">${modifiedLink}</a></p>
                </div>
                <p><a href="/">← Go Back to Dashboard</a></p>
            </body>
            </html>
        `);
    });
});

// 3. TRACKING AND AUTOMATIC REDIRECTION
app.get('/t/:id', (req, res) => {
    const id = req.params.id;

    // Query database for original link destination
    db.get(`SELECT original_url FROM links WHERE id = ?`, [id], async (err, row) => {
        if (err || !row) {
            return res.status(404).send('Resource unavailable or invalid link parameter.');
        }

        const targetUrl = row.original_url;

        // Gather browser and connection signatures
        let rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'] || 'Unknown Browser Signature';
        
        if (rawIp === '::1' || rawIp === '127.0.0.1') {
            rawIp = '8.8.8.8'; // Fallback mock public IP for internal testing
        } else if (rawIp.includes('::ffff:')) {
            rawIp = rawIp.replace('::ffff:', '');
        }

        let geoData = { country: 'Unknown', region: 'Unknown', city: 'Unknown', isp: 'Unknown' };

        // Fetch location details from public geolocation database API
        try {
            const response = await axios.get(`http://ip-api.com{rawIp}`);
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

        // Format system log
        const timestamp = new Date().toISOString();
        const logString = `[${timestamp}] ID: ${id} | Dest: ${targetUrl} | IP: ${rawIp} | Geo: ${geoData.city}, ${geoData.region}, ${geoData.country} | ISP: ${geoData.isp} | Browser: ${userAgent}\n`;

        // Commit network metrics asynchronously to file
        fs.appendFile('ip_log.txt', logString, (err) => {
            if (err) console.error('Disk logging failure:', err);
        });

        // Fast client redirection response
        res.redirect(targetUrl);
    });
});

app.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`Server fully operational on http://localhost:${PORT}`);
    console.log(`Security Notice: Only requests with valid passwords will generate links.`);
    console.log(`=================================================\n`);
});
