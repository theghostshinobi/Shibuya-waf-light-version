import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/api': {
				target: 'http://127.0.0.1:9090',
				changeOrigin: true,
				rewrite: (path: string) => path.replace(/^\/api/, ''),
				configure: (proxy: any) => {
					proxy.on('error', (_err: any, _req: any, res: any) => {
						if (!res.headersSent) {
							res.writeHead(502, { 'Content-Type': 'application/json' });
							res.end(JSON.stringify({ error: 'Backend offline', detail: 'WAF backend on port 9090 is not running' }));
						}
					});
				}
			}
		}
	}
});
