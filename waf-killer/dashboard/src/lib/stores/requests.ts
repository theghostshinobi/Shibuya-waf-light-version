import { writable } from 'svelte/store';
import type { RequestSummary } from '$lib/types';

export interface RequestFilters {
    action: string;
    timeRange: string;
    search: string;
}

function createRequestsStore() {
    const { subscribe, set, update } = writable<{
        items: RequestSummary[];
        total: number;
        page: number;
        loading: boolean;
        filters: RequestFilters;
    }>({
        items: [],
        total: 0,
        page: 1,
        loading: false,
        filters: {
            action: 'all',
            timeRange: '1h',
            search: ''
        }
    });

    return {
        subscribe,
        addRequest: (req: RequestSummary) => update(s => {
            // Respect filters if needed, but for live view generally we append
            // Or maybe only append if it matches?
            // For simplicity, we stick to live feed at top
            const newItems = [req, ...s.items].slice(0, 100);
            return { ...s, items: newItems, total: s.total + 1 };
        }),
        setPage: (page: number) => update(s => ({ ...s, page })),
        updateFilters: (filters: Partial<RequestFilters>) => update(s => ({
            ...s,
            filters: { ...s.filters, ...filters }
        })),
        connect: (initialFilters?: Partial<RequestFilters>) => {
            // Initial load logic via API could go here
            // fetch('/api/requests')...
        }
    };
}

export const requestsStore = createRequestsStore();
