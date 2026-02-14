import { writable } from 'svelte/store';
import type { Stats } from '$lib/types';

function createStatsStore() {
    const { subscribe, set, update } = writable<Stats>({
        total_requests: 0,
        blocked_requests: 0,
        allowed_requests: 0,
        avg_latency_ms: 0,
        rules_triggered: 0,
        ml_detections: 0,
        threat_intel_blocks: 0,
        ebpf_drops: 0,
        requests_per_sec: 0,
        block_rate: 0,
        ml_detection_rate: 0,
        timeline: [],
        attackTypes: [],
        topBlockedIPs: []
    });

    return {
        subscribe,
        updateStats: (data: Partial<Stats>) => update(s => ({ ...s, ...data })),
        connect: () => {
            // Could trigger initial fetch
        }
    };
}

export const statsStore = createStatsStore();
