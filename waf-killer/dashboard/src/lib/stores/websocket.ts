import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import { requestsStore } from './requests';
import { statsStore } from './stats';
import type { RequestSummary, Stats } from '$lib/types';

function createWebSocketStore() {
    const { subscribe, set, update } = writable({
        connected: false
    });

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    function connect() {
        if (!browser) return;
        if (ws) return;

        // In prod use env, in dev assume localhost:9091
        const wsUrl = 'ws://localhost:9091/ws';

        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('WS Connected');
            update(s => ({ ...s, connected: true }));
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'NewRequest') {
                    // Check "data" field inside msg if struct is { type: ..., data: ... }
                    // Based on backend implementation: #[serde(tag = "type", content = "data")]
                    // enum Event { NewRequest(RequestSummary), ... }
                    // Serde with tag="type", content="data" produces { "type": "NewRequest", "data": { ... } }
                    requestsStore.addRequest(msg.data);
                } else if (msg.type === 'StatsUpdate') {
                    statsStore.updateStats(msg.data);
                }
            } catch (e) {
                console.error('WS Parse error', e);
            }
        };

        ws.onclose = () => {
            console.log('WS Disconnected');
            update(s => ({ ...s, connected: false }));
            ws = null;
            clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(connect, 3000);
        };
    }

    return { subscribe, connect };
}

export const websocketStore = createWebSocketStore();
