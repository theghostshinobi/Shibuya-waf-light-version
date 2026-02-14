const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = 3000;

// ═══════════════════════════════════════════════════
// 🎯 DELIBERATELY VULNERABLE WEB APP — FOR WAF TESTING
// ═══════════════════════════════════════════════════
// This app has intentional vulnerabilities:
// - SQL Injection (simulated)
// - XSS (Reflected)
// - Path Traversal
// - Command Injection
// - SSRF
// - Open Redirect
// - Header Injection
// DO NOT DEPLOY IN PRODUCTION

// Fake "database" 
const users = [
    { id: 1, name: 'admin', email: 'admin@vuln.app', password: 'admin123' },
    { id: 2, name: 'user1', email: 'user1@vuln.app', password: 'pass456' },
    { id: 3, name: 'guest', email: 'guest@vuln.app', password: 'guest789' },
];

const products = [
    { id: 1, name: 'Widget A', price: 29.99, description: 'A great widget' },
    { id: 2, name: 'Gadget B', price: 49.99, description: 'An awesome gadget' },
    { id: 3, name: 'Tool C', price: 19.99, description: 'A handy tool' },
];

function parseBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch { resolve(body); }
        });
    });
}

const server = http.createServer(async (req, res) => {
    const parsed = url.parse(req.url, true);
    const pathname = parsed.pathname;
    const query = parsed.query;

    // CORS headers (permissive for testing)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    try {
        // ──────────────────────────────────────────
        // HOME — Simple HTML page
        // ──────────────────────────────────────────
        if (pathname === '/' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<!DOCTYPE html><html><head><title>Vuln App</title></head>
            <body style="font-family:monospace;background:#111;color:#0f0;padding:40px">
                <h1>🎯 Deliberately Vulnerable App</h1>
                <p>This app has intentional security flaws for WAF testing.</p>
                <h2>Endpoints:</h2>
                <ul>
                    <li>GET /search?q=... (XSS)</li>
                    <li>GET /user?id=... (SQLi)</li>
                    <li>GET /file?name=... (Path Traversal)</li>
                    <li>POST /exec {"cmd":"..."} (Command Injection)</li>
                    <li>GET /redirect?url=... (Open Redirect)</li>
                    <li>GET /products (Safe listing)</li>
                    <li>POST /login {"email":"...","password":"..."} (SQLi in login)</li>
                    <li>GET /ping?host=... (SSRF/Command Injection)</li>
                    <li>GET /health (Health check)</li>
                </ul>
                <p style="color:#f00">⚠️ DO NOT DEPLOY IN PRODUCTION</p>
            </body></html>`);
        }

        // ──────────────────────────────────────────
        // HEALTH CHECK
        // ──────────────────────────────────────────
        else if (pathname === '/health') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 1: Reflected XSS
        // ──────────────────────────────────────────
        else if (pathname === '/search' && req.method === 'GET') {
            const q = query.q || '';
            // Directly reflecting user input in HTML — XSS vulnerable!
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`<html><body>
                <h2>Search Results for: ${q}</h2>
                <p>No results found for "${q}"</p>
            </body></html>`);
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 2: SQL Injection (simulated)
        // ──────────────────────────────────────────
        else if (pathname === '/user' && req.method === 'GET') {
            const id = query.id || '1';
            // Simulating vulnerable SQL query
            const simulatedQuery = `SELECT * FROM users WHERE id = ${id}`;
            const user = users.find(u => u.id === parseInt(id));
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                query: simulatedQuery,
                result: user || { error: 'User not found' }
            }));
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 3: Path Traversal
        // ──────────────────────────────────────────
        else if (pathname === '/file' && req.method === 'GET') {
            const name = query.name || 'readme.txt';
            // Directly using user input in file path — path traversal!
            const filePath = path.join(__dirname, 'public', name);
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                res.end(content);
            } catch {
                res.end(`File not found: ${name}`);
            }
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 4: Command Injection
        // ──────────────────────────────────────────
        else if (pathname === '/exec' && req.method === 'POST') {
            const body = await parseBody(req);
            const cmd = body.cmd || 'echo hello';
            // Directly executing user commands!
            res.writeHead(200, { 'Content-Type': 'application/json' });
            try {
                const output = execSync(cmd, { timeout: 5000 }).toString();
                res.end(JSON.stringify({ command: cmd, output }));
            } catch (e) {
                res.end(JSON.stringify({ command: cmd, error: e.message }));
            }
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 5: Open Redirect
        // ──────────────────────────────────────────
        else if (pathname === '/redirect') {
            const target = query.url || '/';
            // No validation of redirect target!
            res.writeHead(302, { Location: target });
            res.end();
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 6: SQLi in Login
        // ──────────────────────────────────────────
        else if (pathname === '/login' && req.method === 'POST') {
            const body = await parseBody(req);
            const email = body.email || '';
            const password = body.password || '';
            // Simulated vulnerable SQL
            const simulatedQuery = `SELECT * FROM users WHERE email='${email}' AND password='${password}'`;
            const user = users.find(u => u.email === email && u.password === password);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                query: simulatedQuery,
                authenticated: !!user,
                user: user ? { id: user.id, name: user.name } : null
            }));
        }

        // ──────────────────────────────────────────
        // 🔴 VULN 7: SSRF / Command Injection via ping
        // ──────────────────────────────────────────
        else if (pathname === '/ping' && req.method === 'GET') {
            const host = query.host || 'localhost';
            // Directly using user input in system command!
            res.writeHead(200, { 'Content-Type': 'application/json' });
            try {
                const output = execSync(`ping -c 1 ${host}`, { timeout: 5000 }).toString();
                res.end(JSON.stringify({ host, output }));
            } catch (e) {
                res.end(JSON.stringify({ host, error: e.message }));
            }
        }

        // ──────────────────────────────────────────
        // SAFE: Products listing
        // ──────────────────────────────────────────
        else if (pathname === '/products' && req.method === 'GET') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(products));
        }

        // ──────────────────────────────────────────
        // 404 fallback
        // ──────────────────────────────────────────
        else {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Not Found', path: pathname }));
        }

    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
    }
});

server.listen(PORT, () => {
    console.log(`\n🎯 Vulnerable App listening on http://localhost:${PORT}`);
    console.log('⚠️  DO NOT DEPLOY IN PRODUCTION\n');
});
