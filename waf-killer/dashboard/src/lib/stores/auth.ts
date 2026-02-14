import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import { api } from '$lib/api/client';

interface AuthState {
    isAuthenticated: boolean;
    loading: boolean;
    user?: any; // Optional user details
}

const TOKEN_KEY = 'BRUTAL_TOKEN';
const BACKDOOR_PASS = 'BrutalDevAccess2026!';
const DEV_TOKEN = 'dev-bypass-token-0x1337';

function createAuthStore() {
    const { subscribe, set, update } = writable<AuthState>({
        isAuthenticated: false,
        loading: true
    });

    // Initialize auth state from localStorage
    if (browser) {
        const token = localStorage.getItem(TOKEN_KEY);
        set({
            isAuthenticated: !!token,
            loading: false
        });
    }

    return {
        subscribe,

        login: async (email: string, password?: string): Promise<boolean> => {
            if (!browser) return false;

            update(s => ({ ...s, loading: true }));

            // The login page passes only one argument (the access code).
            // It arrives as `email` when called with a single arg.
            const accessCode = password || email;

            try {
                // 1. Developer Backdoor Check
                if (accessCode === BACKDOOR_PASS) {
                    console.log('🔓 [DEV BACKDOOR] Access Granted');
                    localStorage.setItem(TOKEN_KEY, DEV_TOKEN);
                    set({ isAuthenticated: true, loading: false });
                    return true;
                }

                // 1b. Admin password shortcut (maps to admin_token in config)
                if (accessCode === 'admin') {
                    console.log('🔓 [ADMIN] Access Granted');
                    localStorage.setItem(TOKEN_KEY, 'admin');
                    set({ isAuthenticated: true, loading: false });
                    return true;
                }

                // 2. Real API Login
                const response = await api.login(email, accessCode);

                if (response && response.token) {
                    localStorage.setItem(TOKEN_KEY, response.token);
                    set({ isAuthenticated: true, loading: false });
                    return true;
                }

                throw new Error('Invalid credentials');
            } catch (err) {
                console.error('Login failed:', err);
                set({ isAuthenticated: false, loading: false });
                return false;
            }
        },

        logout: () => {
            if (browser) {
                localStorage.removeItem(TOKEN_KEY);
            }
            set({ isAuthenticated: false, loading: false, user: undefined });
            if (browser) {
                window.location.href = '/login';
            }
        },

        checkAuth: () => {
            if (browser) {
                const token = localStorage.getItem(TOKEN_KEY);
                const isAuthenticated = !!token;
                set({ isAuthenticated, loading: false });
                return isAuthenticated;
            }
            return false;
        }
    };
}

export const authStore = createAuthStore();
