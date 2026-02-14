import { writable } from 'svelte/store';

export interface Tenant {
    id: string;
    slug: string;
    name: string;
    plan: string;
    status: string;
    settings: any;
    quotas: any;
}

function createTenantStore() {
    const { subscribe, set, update } = writable<Tenant | null>(null);

    return {
        subscribe,
        set,
        update,
        fetch: async () => {
            try {
                const res = await fetch('/api/tenant');
                if (res.ok) {
                    const data = await res.json();
                    set(data);
                }
            } catch (e) {
                console.error('Failed to fetch tenant', e);
            }
        },
        updateSettings: async (settings: any) => {
            try {
                const res = await fetch('/api/tenant/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
                if (res.ok) {
                    const data = await res.json();
                    set(data);
                }
            } catch (e) {
                console.error('Failed to update tenant settings', e);
            }
        }
    };
}

export const tenant = createTenantStore();
