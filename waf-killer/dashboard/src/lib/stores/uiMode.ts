import { writable } from 'svelte/store';
import { browser } from '$app/environment';

export type UIMode = 'simple' | 'advanced';

const STORAGE_KEY = 'waf_ui_mode';

function createUIModeStore() {
    // Get initial value from localStorage or default to 'simple'
    let initialMode: UIMode = 'simple';
    if (browser) {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored === 'advanced') {
            initialMode = 'advanced';
        }
    }

    const { subscribe, set, update } = writable<UIMode>(initialMode);

    return {
        subscribe,

        toggle: () => {
            update(mode => {
                const newMode = mode === 'simple' ? 'advanced' : 'simple';
                if (browser) {
                    localStorage.setItem(STORAGE_KEY, newMode);
                }
                return newMode;
            });
        },

        setMode: (mode: UIMode) => {
            if (browser) {
                localStorage.setItem(STORAGE_KEY, mode);
            }
            set(mode);
        }
    };
}

export const uiModeStore = createUIModeStore();
