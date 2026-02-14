// ===============================================
// Vulnerable Target App — Shibuya WAF Stress Test
// ===============================================
// A deliberately vulnerable Express.js server.
// DO NOT deploy this to production. Ever.
// ===============================================

const http = require('http');
const url = require('url');
const querystring = require('querystring');

const PORT = 3000;

// Simple router
function handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const query = parsedUrl.query;
    const method = req.method;

    // Collect body for POST requests
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
        // CORS headers (allow everything)
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', '*');
        res.setHeader('Access-Control-Allow-Headers', '*');

        // Route dispatch
        try {
            if (path === '/' && method === 'GET') {
                return sendHTML(res, `
                    <html><head><title>Vulnerable App</title></head>
                    <body style="background:#111;color:#0f0;font-family:monospace;padding:40px">
                        <h1>☠️ Vulnerable Target App</h1>
                        <p>This server is intentionally vulnerable for WAF testing.</p>
                        <ul>
                            <li>GET /search?q=test</li>
                            <li>GET /user/1</li>
                            <li>POST /login (JSON: user, pass)</li>
                            <li>GET /file?name=readme.txt</li>
                            <li>POST /api/data (JSON body)</li>
                            <li>GET /admin</li>
                            <li>GET /health</li>
                            <li>POST /xml (XML body)</li>
                            <li>GET /redirect?url=...</li>
                        </ul>
                    </body></html>
                `);
            }

            // --- SEARCH (XSS target) ---
            if (path === '/search' && method === 'GET') {
                const q = query.q || '';
                // Deliberately reflects input without sanitization
                return sendHTML(res, `
                    <html><body style="background:#111;color:#0f0;font-family:monospace;padding:40px">
                    <h2>Search Results for: ${q}</h2>
                    <p>No results found for "${q}"</p>
                    </body></html>
                `);
            }

            // --- USER (SQLi target) ---
            if (path.startsWith('/user/')) {
                const userId = path.split('/')[2];
                // Deliberately "uses" input in a fake SQL query
                const fakeQuery = `SELECT * FROM users WHERE id = '${userId}'`;
                return sendJSON(res, {
                    query: fakeQuery,
                    user: { id: userId, name: 'TestUser', email: 'test@test.com' }
                });
            }

            // --- LOGIN (credential stuffing target) ---
            if (path === '/login' && method === 'POST') {
                let parsed = {};
                try { parsed = JSON.parse(body); } catch (e) { parsed = querystring.parse(body); }
                const fakeAuth = `SELECT * FROM users WHERE user='${parsed.user}' AND pass='${parsed.pass}'`;
                return sendJSON(res, {
                    query: fakeAuth,
                    success: parsed.user === 'admin' && parsed.pass === 'admin',
                    token: 'fake-jwt-token-12345'
                });
            }

            // --- FILE (LFI/RFI target) ---
            if (path === '/file' && method === 'GET') {
                const name = query.name || 'index.html';
                // Deliberately doesn't sanitize path
                return sendJSON(res, {
                    file: name,
                    content: `[Simulated content of ${name}]`,
                    path: `/var/www/files/${name}`
                });
            }

            // --- API DATA (injection target) ---
            if (path === '/api/data' && method === 'POST') {
                let parsed = {};
                try { parsed = JSON.parse(body); } catch (e) { /* ignore */ }
                return sendJSON(res, {
                    received: parsed,
                    processed: true,
                    echo: body
                });
            }

            // --- ADMIN (auth bypass target) ---
            if (path === '/admin') {
                return sendHTML(res, `
                    <html><body style="background:#111;color:#f00;font-family:monospace;padding:40px">
                    <h1>🔒 Admin Panel</h1>
                    <p>Welcome, administrator!</p>
                    <p>Secret data: DATABASE_PASSWORD=hunter2</p>
                    </body></html>
                `);
            }

            // --- XML endpoint (XXE target) ---
            if (path === '/xml' && method === 'POST') {
                return sendJSON(res, {
                    received: true,
                    xml_length: body.length,
                    echo: body.substring(0, 200)
                });
            }

            // --- REDIRECT (SSRF target) ---
            if (path === '/redirect') {
                const target = query.url || '/';
                // Deliberately follows any URL
                return sendJSON(res, {
                    redirecting_to: target,
                    status: 'would_redirect'
                });
            }

            // --- HEALTH CHECK ---
            if (path === '/health') {
                return sendJSON(res, { status: 'ok', uptime: process.uptime() });
            }

            // 404 for everything else
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Not Found', path }));

        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
    });
}

function sendHTML(res, html) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
}

function sendJSON(res, data) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
}

const server = http.createServer(handleRequest);
server.listen(PORT, () => {
    console.log(`\n☠️  Vulnerable Target App running on http://localhost:${PORT}`);
    console.log('⚠️  This server is INTENTIONALLY VULNERABLE. Do NOT expose to the internet.\n');
});
