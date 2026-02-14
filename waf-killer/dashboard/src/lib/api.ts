import { authStore } from './stores/auth';
import type {
    DashboardStats,
    DiscoveredEndpoint,
    WafConfig,
    HealthStatus,
    RequestLog,
    RuleInfo,
    Vulnerability,
    VirtualPatch,
    AnalyticsData,
    TrafficTimeSeries
} from './types';

const API_BASE = '/api'; // Proxied to 9090 by Vite

export const api = {
    // Fix 1: Change /analytics to /stats
    async getStats(): Promise<DashboardStats> {
        const res = await fetch(`${API_BASE}/stats`);
        if (!res.ok) throw new Error('Failed to fetch stats');
        return res.json();
    },

    async getTrafficHistory(): Promise<TrafficTimeSeries[]> {
        const res = await fetch(`${API_BASE}/analytics/timeseries`);
        if (!res.ok) throw new Error('Failed to fetch traffic history');
        return res.json();
    },

    async getAttackBreakdown(): Promise<{ category: string; display_name: string; count: number }[]> {
        const res = await fetch(`${API_BASE}/analytics/attacks`);
        if (!res.ok) throw new Error('Failed to fetch attack breakdown');
        return res.json();
    },

    async panic(): Promise<{ success: boolean; message: string }> {
        const res = await fetch(`${API_BASE}/api/system/panic`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to activate Panic Mode');
        return res.json();
    },

    // Legacy Analytics support (mapping stats to AnalyticsData)
    async getAnalytics(): Promise<AnalyticsData> {
        try {
            const stats = await this.getStats();
            return {
                total_requests: stats.total_requests,
                blocked_requests: stats.blocked_requests,
                block_rate: stats.total_requests > 0 ? (stats.blocked_requests / stats.total_requests) * 100 : 0,
                active_rules: stats.rules_triggered // Approximation
            };
        } catch (e) {
            console.error(e);
            return { total_requests: 0, blocked_requests: 0, block_rate: 0, active_rules: 0 };
        }
    },

    // Fix 2: Change /shadow-api to /shadow-api/endpoints
    async getShadowApiEndpoints(): Promise<DiscoveredEndpoint[]> {
        const res = await fetch(`${API_BASE}/shadow-api/endpoints`);
        if (!res.ok) throw new Error('Failed to fetch shadow API');
        return res.json();
    },

    // Alias for existing code
    async getShadowApi(): Promise<DiscoveredEndpoint[]> {
        return this.getShadowApiEndpoints();
    },

    // Fix 3: Change /config/update to /config
    async updateConfig(config: any): Promise<{ success: boolean; message: string }> {
        const res = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config }) // Backend expects wrapped config
        });
        if (!res.ok) throw new Error('Failed to update config');
        return res.json();
    },

    // Add: Get config endpoint
    async getConfig(): Promise<any> {
        const res = await fetch(`${API_BASE}/config`);
        if (!res.ok) throw new Error('Failed to fetch config');
        return res.json();
    },

    async getHealth(): Promise<HealthStatus> {
        const res = await fetch(`${API_BASE}/health`);
        return res.json();
    },

    async getLogs(): Promise<RequestLog[]> {
        const res = await fetch(`${API_BASE}/logs`);
        return res.json();
    },

    async getRules(): Promise<RuleInfo[]> {
        const res = await fetch(`${API_BASE}/rules`);
        return res.json();
    },

    // Stub for vulnerabilities (not implemented yet)
    async getVulnerabilities(): Promise<Vulnerability[]> {
        const res = await fetch(`${API_BASE}/vulnerabilities`);
        if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
        return res.json();
    },

    async startScan(): Promise<any> {
        const res = await fetch(`${API_BASE}/vulnerabilities/scan`, {
            method: 'POST'
        });
        return res.json();
    },

    async getVirtualPatches(): Promise<VirtualPatch[]> {
        const res = await fetch(`${API_BASE}/virtual-patches`);
        return res.json();
    },

    async updateRule(id: string, updates: { enabled: boolean; action?: string }): Promise<any> {
        const res = await fetch(`${API_BASE}/rules/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates)
        });
        if (!res.ok) throw new Error('Failed to update rule');
        return res.json();
    },

    async toggleModule(name: 'ebpf' | 'ml'): Promise<{ enabled: boolean }> {
        const res = await fetch(`${API_BASE}/toggle-module/${name}`, {
            method: 'POST'
        });
        return res.json();
    },

    async getWasmPlugins(): Promise<any[]> {
        const res = await fetch(`${API_BASE}/modules/wasm`);
        return res.json();
    },

    async lookupIp(ip: string): Promise<any> {
        const res = await fetch(`${API_BASE}/threat/lookup?ip=${ip}`);
        // Handle 404 as valid "Clean" response if body exists, or just return json
        if (!res.ok && res.status !== 404) throw new Error('Lookup failed');
        return res.json();
    },

    async uploadWasmPlugin(file: File): Promise<{ success: boolean; message: string }> {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch(`${API_BASE}/modules/wasm/upload`, {
            method: 'POST',
            body: formData
        });
        return res.json();
    },

    // ========================================
    // Rules CRUD Operations
    // ========================================

    async deleteRule(id: string): Promise<{ success: boolean; message?: string }> {
        const res = await fetch(`${API_BASE}/rules/${id}`, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error('Failed to delete rule');
        return res.json();
    },

    async createRule(rule: {
        name: string;
        pattern: string;
        risk_score: number;
        action: string;
        description: string;
    }): Promise<RuleInfo> {
        const res = await fetch(`${API_BASE}/rules`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rule)
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Failed to create rule');
        }
        return res.json();
    },

    // ========================================
    // Threat Intelligence
    // ========================================

    async getThreatFeeds(): Promise<Array<{
        name: string;
        count: number;
        status: string;
        last_updated: string;
    }>> {
        const res = await fetch(`${API_BASE}/threat/feeds`);
        if (!res.ok) throw new Error('Failed to fetch threat feeds');
        return res.json();
    },

    // ========================================
    // Module Status (without toggle)
    // ========================================

    async getModuleStatus(name: 'ebpf' | 'ml'): Promise<{ enabled: boolean; module: string }> {
        const res = await fetch(`${API_BASE}/module-status/${name}`);
        if (!res.ok) {
            // Default to enabled if endpoint fails
            return { enabled: true, module: name };
        }
        return res.json();
    }
};


// Export individual functions for direct import as requested
export const getStats = api.getStats;
export const getShadowApiEndpoints = api.getShadowApiEndpoints;
export const updateConfig = api.updateConfig;
export const getConfig = api.getConfig;
export const getVulnerabilities = api.getVulnerabilities;
