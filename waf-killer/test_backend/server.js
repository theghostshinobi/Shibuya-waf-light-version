const http = require('http');
const url = require('url');

const PORT = 3000;

const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url, true);
    let body = '';

    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        // Log request
        const logEntry = {
            timestamp: new Date().toISOString(),
            method: req.method,
            path: parsedUrl.pathname,
            query: parsedUrl.query,
            headers: req.headers,
            body: body
        };
        console.log(JSON.stringify(logEntry));

        // Set common headers
        res.setHeader('Content-Type', 'application/json');

        // Router
        if (parsedUrl.pathname === '/health') {
            res.writeHead(200);
            res.end(JSON.stringify({ status: 'ok' }));
        } else if (parsedUrl.pathname === '/api/users') {
            res.writeHead(200);
            res.end(JSON.stringify({
                users: [
                    { id: 1, name: "Alice", email: "alice@example.com" },
                    { id: 2, name: "Bob", email: "bob@example.com" }
                ]
            }));
        } else if (parsedUrl.pathname === '/api/graphql') {
            // Mock GraphQL - accepts anything
            res.writeHead(200);
            res.end(JSON.stringify({ data: { user: { name: "Test User" } } }));
        } else if (parsedUrl.pathname === '/api/data') {
            // Mock Data endpoint - accepts anything
            res.writeHead(200);
            res.end(JSON.stringify({ received: true }));
        } else if (parsedUrl.pathname === '/api/search') {
            // Mock Search - accepts anything
            res.writeHead(200);
            res.end(JSON.stringify({ results: ["item1", "item2"], query: parsedUrl.query.q }));
        } else if (parsedUrl.pathname === '/.env' || parsedUrl.pathname === '/swagger.json' || parsedUrl.pathname === '/.git/config') {
            // Mock sensitive files - should be blocked by WAF, but if it hits here, it returns 200 (vulnerable)
            res.writeHead(200);
            res.end(JSON.stringify({ secret: "SUPER_SECRET_KEY" }));
        } else {
            // Catch-all
            res.writeHead(200);
            res.end(JSON.stringify({ message: "path not specifically mocked but allowed" }));
        }
    });
});

server.listen(PORT, () => {
    console.log(`Vulnerable backend listening on port ${PORT}`);
});
