import { writable } from 'svelte/store';

export interface Activity {
    id: string;
    user_name: string;
    action: any;
    created_at: string;
}

function createActivityStore() {
    const { subscribe, set, update } = writable<Activity[]>([]);

    return {
        subscribe,
        fetch: async (limit = 50) => {
            try {
                const res = await fetch(`/api/activity?limit=${limit}`);
                if (res.ok) {
                    const data = await res.json();
                    set(data);
                }
            } catch (e) {
                console.error('Failed to fetch activity', e);
            }
        },
        add: (activity: Activity) => update(n => [activity, ...n])
    };
}

export const activityStore = createActivityStore();
