const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const UAParser = require('ua-parser-js');
const session = require('express-session');
const axios = require('axios');
const app = express();
const port = process.env.PORT || 3000;

require('dotenv').config();

// Enable trust proxy to get the correct IP address behind a proxy
app.set('trust proxy', true);

// Set up EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware to parse URL-encoded data (for form submissions) and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Function to extract the real client IP from X-Forwarded-For header
const getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    const rawIp = req.ip;
    const debugInfo = {
        xForwardedFor: forwarded,
        rawIp: rawIp,
        headers: req.headers,
        timestamp: new Date().toISOString()
    };
    console.log('IP Debug Log:', JSON.stringify(debugInfo, null, 2));

    let clientIp = rawIp;
    if (forwarded) {
        const ipList = forwarded.split(',').map(ip => ip.trim());
        clientIp = ipList[0];
    }

    if (clientIp === '::1') {
        clientIp = '127.0.0.1';
    }

    return clientIp;
};

// Middleware to log visitor info on every request
app.use(async (req, res, next) => {
    const ip = getClientIp(req);
    const parser = new UAParser();
    const uaResult = parser.setUA(req.get('User-Agent')).getResult();

    let geoData = {};
    try {
        const reservedIps = ['127.0.0.1', 'localhost'];
        const isPrivateIp = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') || ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') || ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') || ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') || ip.startsWith('172.31.');
        if (reservedIps.includes(ip) || isPrivateIp) {
            geoData = { status: 'skipped', message: 'Reserved or private IP address (likely local testing or internal network)', query: ip };
        } else {
            const geoResponse = await axios.get(`http://ip-api.com/json/${ip}`);
            geoData = geoResponse.data;
            if (geoData.status === 'fail') {
                geoData.message = geoData.message || 'Geolocation failed for this IP';
            }
        }
    } catch (error) {
        console.error('Error fetching geolocation:', error);
        geoData = { status: 'error', message: 'Geolocation unavailable', error: error.message, query: ip };
    }

    const visitorInfo = {
        ip: ip,
        userAgent: req.get('User-Agent'),
        device: {
            browser: uaResult.browser,
            os: uaResult.os,
            device: uaResult.device
        },
        headers: req.headers,
        queryParams: req.query,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString(),
        geolocation: geoData,
        sessionId: req.sessionID
    };

    console.log('Visitor Log:', JSON.stringify(visitorInfo, null, 2));

    next();
});

// Home page with username input form
app.get('/', (req, res) => {
    res.render('index', { message: null });
});

// Handle username submission and redirect to Discord OAuth2
app.post('/submit-username', async (req, res) => {
    const { username, email, customField } = req.body;
    if (!username) {
        return res.render('index', { message: 'Please enter a username.' });
    }

    const ip = getClientIp(req);
    const parser = new UAParser();
    const uaResult = parser.setUA(req.get('User-Agent')).getResult();

    let geoData = {};
    try {
        const reservedIps = ['127.0.0.1', 'localhost'];
        const isPrivateIp = ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.') || ip.startsWith('172.17.') || ip.startsWith('172.18.') || ip.startsWith('172.19.') || ip.startsWith('172.20.') || ip.startsWith('172.21.') || ip.startsWith('172.22.') || ip.startsWith('172.23.') || ip.startsWith('172.24.') || ip.startsWith('172.25.') || ip.startsWith('172.26.') || ip.startsWith('172.27.') || ip.startsWith('172.28.') || ip.startsWith('172.29.') || ip.startsWith('172.30.') || ip.startsWith('172.31.');
        if (reservedIps.includes(ip) || isPrivateIp) {
            geoData = { status: 'skipped', message: 'Reserved or private IP address (likely local testing or internal network)', query: ip };
        } else {
            const geoResponse = await axios.get(`http://ip-api.com/json/${ip}`);
            geoData = geoResponse.data;
            if (geoData.status === 'fail') {
                geoData.message = geoData.message || 'Geolocation failed for this IP';
            }
        }
    } catch (error) {
        console.error('Error fetching geolocation:', error);
        geoData = { status: 'error', message: 'Geolocation unavailable', error: error.message, query: ip };
    }

    const usernameLog = {
        submittedUsername: username,
        email: email || 'Not provided',
        customField: customField || 'Not provided',
        ip: ip,
        userAgent: req.get('User-Agent'),
        device: {
            browser: uaResult.browser,
            os: uaResult.os,
            device: uaResult.device
        },
        headers: req.headers,
        referrer: req.get('Referer') || 'Direct',
        timestamp: new Date().toISOString(),
        geolocation: geoData,
        sessionId: req.sessionID
    };

    console.log('Username Log:', JSON.stringify(usernameLog, null, 2));

    const redirectUri = encodeURIComponent(`${process.env.SERVER_URL || `http://localhost:${port}`}/callback`);
    const oauthUrl = `https://discord.com/api/oauth2/authorize?client_id=${process.env.CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=identify`;
    res.redirect(oauthUrl);
});

// OAuth2 callback to authenticate user and log their info
app.get('/callback', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) {
            return res.render('index', { message: 'Error: No code provided.' });
        }

        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                client_id: process.env.CLIENT_ID,
                client_secret: process.env.CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: `${process.env.SERVER_URL || `http://localhost:${port}`}/callback`,
                scope: 'identify'
            })
        });

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        if (!accessToken) {
            return res.render('index', { message: 'Error: Could not retrieve access token.' });
        }

        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        const userData = await userResponse.json();
        const discordUsername = userData.username;
        const userId = userData.id;

        const userLog = { userId, discordUsername, timestamp: new Date().toISOString() };
        console.log('Authenticated User Log:', JSON.stringify(userLog, null, 2));

        res.render('index', { message: 'Apko 3 days k liye Nitro mil gaya hai!' });
    } catch (error) {
        console.error('Error in callback:', error);
        console.error('Callback Error:', error.message);
        res.render('index', { message: 'An error occurred. Please try again.' });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});