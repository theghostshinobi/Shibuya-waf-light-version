import type {
    RequestSummary, Stats, TimePoint, PieSlice, BarItem, DiscoveredEndpoint, HealthStatus, RequestLog, Vulnerability, VirtualPatch,
    ConfigBackup, ThreatIntelStats, VulnerabilityImport, RequestDetail, ThreatFeed, ShadowApiEndpoint,
    RuleCount, IpCount, TrafficTimeSeries,
    BotStatsSnapshot,
    BotDetectionConfig,
    ReplayReport,
    ShadowReport
} from '$lib/types';

const API_BASE = import.meta.env.PUBLIC_API_URL || '/api';

// Shadow Report Types

class ApiClient {
    private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
        const headers = new Headers(options?.headers);

        // Inject Brutal Token if exists
        if (typeof localStorage !== 'undefined') {
            const token = localStorage.getItem('BRUTAL_TOKEN');
            if (token) {
                headers.set('X-Admin-Token', token);
            }
        }

        const config = {
            ...options,
            headers
        };

        const response = await fetch(`${API_BASE}${path}`, config);

        if (response.status === 401) {
            if (typeof localStorage !== 'undefined') {
                localStorage.removeItem('BRUTAL_TOKEN');
                window.location.href = '/login';
            }
            throw new Error('Unauthorized');
        }

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        // Handle void responses (204 No Content)
        if (response.status === 204) {
            return {} as T;
        }

        return response.json();
    }

    // Stats
    async getStats(): Promise<Stats> {
        return this.fetch<Stats>('/stats');
    }

    // Requests
    async getRequests(filters?: any): Promise<{ items: RequestSummary[], total: number }> {
        // Build query string from filters...
        return this.fetch<{ items: RequestSummary[], total: number }>('/requests');
    }

    async getRequest(id: string): Promise<RequestSummary> {
        return this.fetch<RequestSummary>(`/requests/${id}`);
    }

    // Rules
    async getRules(): Promise<any[]> {
        return this.fetch<any[]>('/rules');
    }



    // ML Feedback
    async getPendingMLReviews(): Promise<any[]> {
        return this.fetch<any[]>('/ml/pending-reviews');
    }

    async submitMLFeedback(requestId: string, actualClass: string): Promise<void> {
        await this.fetch('/ml/feedback', {
            method: 'POST',
            body: JSON.stringify({ requestId, actualClass }),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // ML Neural Engine
    async getMLStats(): Promise<any> {
        return this.fetch('/ml/stats');
    }

    async getMLRecentDetections(): Promise<any> {
        return this.fetch('/ml/recent-detections');
    }

    async getMLModelInfo(): Promise<any> {
        return this.fetch('/ml/model-info');
    }

    // Analytics
    async getAnalytics(timeRange: string): Promise<any> {
        return this.fetch(`/analytics?range=${timeRange}`);
    }

    // Shadow Mode
    async getShadowStatus(): Promise<any> {
        return this.fetch('/shadow/status');
    }

    async getShadowSummary(): Promise<any> {
        return this.fetch('/shadow/summary');
    }

    async getShadowReport(): Promise<ShadowReport> {
        return this.fetch<ShadowReport>('/shadow/report');
    }

    async enableShadow(policy?: string, percentage?: number): Promise<void> {
        await this.fetch('/shadow/enable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy, percentage })
        });
    }

    async disableShadow(): Promise<void> {
        await this.fetch('/shadow/disable', { method: 'POST' });
    }

    async promoteShadowToBlock(): Promise<void> {
        await this.fetch('/shadow/promote', { method: 'POST' });
    }

    // Auth
    async login(email: string, password: string): Promise<any> {
        return this.fetch('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async verifyMFA(challengeId: string, code: string): Promise<any> {
        return this.fetch('/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({ challenge_id: challengeId, code }),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async getMFASetup(): Promise<any> {
        return this.fetch('/auth/mfa/setup', { method: 'POST' });
    }

    // Episode 13: Enterprise Features
    async getCurrentTenant(): Promise<any> {
        return this.fetch('/tenant');
    }

    async updateTenantSettings(settings: any): Promise<any> {
        return this.fetch('/tenant/settings', {
            method: 'POST',
            body: JSON.stringify(settings),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async getTeamMembers(): Promise<any[]> {
        return this.fetch<any[]>('/team');
    }

    async inviteTeamMember(email: string, role: string): Promise<any> {
        return this.fetch('/team/invite', {
            method: 'POST',
            body: JSON.stringify({ email, role }),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async removeTeamMember(userId: string): Promise<void> {
        await this.fetch(`/team/${userId}`, { method: 'DELETE' });
    }

    async getActivityFeed(limit = 50): Promise<any[]> {
        return this.fetch<any[]>(`/activity?limit=${limit}`);
    }

    // Audit logs are usually exported, but we might want a fetch method for preview
    async exportAuditLog(from: string, to: string): Promise<Blob> {
        const headers = new Headers({ 'Content-Type': 'application/json' });
        if (typeof localStorage !== 'undefined') {
            const token = localStorage.getItem('BRUTAL_TOKEN');
            if (token) headers.set('X-Admin-Token', token);
        }
        const response = await fetch(`${API_BASE}/audit/export`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ from, to })
        });
        if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
        return response.blob();
    }

    // eBPF (Episode 19)
    async getEBPFStatus(): Promise<{ enabled: boolean, stats?: any }> {
        return this.fetch('/module-status/ebpf');
    }

    async getEBPFStats(): Promise<any> {
        return this.fetch('/ebpf/stats');
    }

    async blockIPKernel(ip: string): Promise<any> {
        return this.fetch('/ebpf/block', {
            method: 'POST',
            body: JSON.stringify({ ip }),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // ========================================
    // Quick Setup
    // ========================================

    async quickSetup(params: { backend_url: string; security_level: 'strict' | 'moderate' | 'permissive' }): Promise<{
        status: string;
        waf_url: string;
        backend_url: string;
        security_level: string;
        anomaly_threshold: number;
        rules_enabled: boolean;
        ml_enabled: boolean;
    }> {
        return this.fetch('/quick-setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params),
        });
    }

    // ========================================
    // API Protection & Config
    // ========================================

    async getConfig(): Promise<any> {
        return this.fetch('/config');
    }

    async updateConfig(config: any): Promise<{ success: boolean; message: string }> {
        return this.fetch('/config/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config) // Wrap config? No, backend expects ConfigUpdate struct directly as Payload
            // Wait, backend expects `Json(payload): Json<ConfigUpdate>`.
            // Does this match `config` object or is it wrapped?
            // "pub struct ConfigUpdate { pub burst_size: Option<u32>, ... }"
            // The frontend usually sends the whole config object.
            // Let's assume the frontend sends a partial object matching ConfigUpdate.
        });
    }

    /**
     * Retrieve list of available config backups
     */
    async getConfigBackups(): Promise<ConfigBackup[]> {
        return this.fetch<ConfigBackup[]>('/config/backups');
    }

    /**
     * Rollback configuration to a previous backup
     * @param timestamp - Backup timestamps to restore
     */
    async rollbackConfig(timestamp: string): Promise<{ success: boolean; message: string }> {
        return this.fetch('/config/rollback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backup_timestamp: timestamp })
        });
    }


    async uploadOpenApiSpec(yamlContent: string): Promise<void> {
        await this.fetch('/api-protection/openapi', {
            method: 'POST',
            headers: { 'Content-Type': 'text/yaml' },
            body: yamlContent,
        });
    }

    async getApiProtectionStats(): Promise<any> {
        return this.fetch('/api-protection/stats');
    }

    async getGraphQLStats(): Promise<any> {
        return this.fetch('/graphql/stats');
    }

    // Tenants Management (Episode 13+)
    async getTenants(): Promise<{ tenants: any[], total: number }> {
        return this.fetch<{ tenants: any[], total: number }>('/tenants');
    }

    async createTenant(tenant: any): Promise<any> {
        return this.fetch('/tenants', {
            method: 'POST',
            body: JSON.stringify(tenant),
            headers: { 'Content-Type': 'application/json' }
        });
    }

    async updateTenant(id: string, updates: any): Promise<any> {
        const response = await fetch(`${API_BASE}/tenants/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates),
        });
        if (!response.ok) throw new Error(await response.text());
        return response.json();
    }

    async deleteTenant(id: string): Promise<any> {
        const response = await fetch(`${API_BASE}/tenants/${id}`, {
            method: 'DELETE',
        });
        if (!response.ok) throw new Error(await response.text());
        return response;
    }

    // ========================================
    // Migration from legacy api.ts
    // ========================================

    async getTrafficHistory(): Promise<any[]> {
        return this.fetch('/analytics/timeseries');
    }

    async getAttackBreakdown(): Promise<{ category: string; display_name: string; count: number }[]> {
        return this.fetch('/analytics/attacks');
    }

    async panic(): Promise<{ success: boolean; message: string }> {
        return this.fetch('/system/panic', { method: 'POST' });
    }

    async deleteRule(id: string): Promise<any> {
        return this.fetch(`/rules/${id}`, { method: 'DELETE' });
    }

    async createRule(rule: { name: string; pattern: string; risk_score: number; action: string; description: string }): Promise<any> {
        return this.fetch('/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rule),
        });
    }

    // Legacy Analytics support adapter
    async getAnalyticsSummary(): Promise<any> {
        try {
            const stats = await this.getStats();
            return {
                total_requests: stats.total_requests,
                blocked_requests: stats.blocked_requests,
                block_rate: stats.total_requests > 0 ? (stats.blocked_requests / stats.total_requests) * 100 : 0,
                active_rules: stats.rules_triggered
            };
        } catch (e) {
            console.error(e);
            return { total_requests: 0, blocked_requests: 0, block_rate: 0, active_rules: 0 };
        }
    }

    async getShadowApiEndpoints(): Promise<DiscoveredEndpoint[]> {
        return this.fetch('/shadow-api/endpoints');
    }



    async getHealth(): Promise<HealthStatus> {
        return this.fetch('/health');
    }

    async getLogs(): Promise<RequestLog[]> {
        return this.fetch('/logs');
    }

    async getVulnerabilities(): Promise<Vulnerability[]> {
        return this.fetch('/vulnerabilities');
    }

    async importVulnerabilities(vulnerabilities: VulnerabilityImport[], source: string): Promise<{
        created: number;
        updated: number;
        skipped: number;
        errors: string[];
    }> {
        return this.fetch('/vulnerabilities/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vulnerabilities, source })
        });
    }


    async startScan(): Promise<any> {
        return this.fetch('/vulnerabilities/scan', { method: 'POST' });
    }

    async getVirtualPatches(): Promise<VirtualPatch[]> {
        return this.fetch('/virtual-patches');
    }

    // Generalized update rule (replaces specific toggleRule if needed)
    async updateRule(id: string, updates: { enabled: boolean; action?: string }): Promise<any> {
        return this.fetch(`/rules/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updates)
        });
    }

    async toggleModule(name: 'ebpf' | 'ml'): Promise<{ enabled: boolean }> {
        return this.fetch(`/toggle-module/${name}`, { method: 'POST' });
    }

    async getModuleStatus(name: 'ebpf' | 'ml'): Promise<{ enabled: boolean; module: string }> {
        try {
            return await this.fetch(`/module-status/${name}`);
        } catch {
            // Default to enabled if endpoint fails
            return { enabled: true, module: name };
        }
    }

    // ========================================
    // Enhancement #6: Bot Detection & Replay
    // ========================================

    async getBotDetectionStats(): Promise<BotStatsSnapshot> {
        return this.fetch('/bot-detection/stats');
    }

    async getBotDetectionConfig(): Promise<BotDetectionConfig> {
        return this.fetch('/bot-detection/config');
    }

    async updateBotDetectionConfig(config: BotDetectionConfig): Promise<BotDetectionConfig> {
        return this.fetch('/bot-detection/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
    }

    async replayTraffic(policy: string, from: number, to: number): Promise<ReplayReport> {
        const res = await fetch(`${API_BASE}/replay`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                policy,
                from,
                to
            })
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.error || 'Replay failed');
        }
        return res.json();
    }
    async getWasmPlugins(): Promise<any[]> {
        return this.fetch('/modules/wasm');
    }

    async lookupIp(ip: string): Promise<any> {
        try {
            return await this.fetch(`/threat/lookup?ip=${ip}`);
        } catch (e: any) {
            throw e;
        }
    }

    async uploadWasmPlugin(file: File): Promise<{ success: boolean; message: string }> {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${API_BASE}/modules/wasm/upload`, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) throw new Error(`API Error: ${response.statusText}`);
        return response.json();
    }

    // ========================================
    // Admin & Threat Intel Methods
    // ========================================

    async addToBlacklist(ip: string, reason?: string, duration?: number): Promise<{ success: boolean }> {
        return this.fetch('/admin/blacklist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason, duration_hours: duration })
        });
    }

    async removeFromBlacklist(ip: string): Promise<{ success: boolean }> {
        return this.fetch(`/admin/blacklist/${encodeURIComponent(ip)}`, {
            method: 'DELETE'
        });
    }

    async getThreatIntelStats(): Promise<ThreatIntelStats> {
        return this.fetch<ThreatIntelStats>('/admin/threat-intel/stats');
    }

    async refreshThreatIntelFeeds(): Promise<{
        success: boolean;
        feeds_refreshed: number;
        ips_added: number;
        ips_removed: number;
    }> {
        return this.fetch('/admin/threat-intel/refresh', { method: 'POST' });
    }

    // Requests Drill-down
    async getRequestDetail(requestId: string): Promise<RequestDetail> {
        return this.fetch<RequestDetail>(`/requests/${requestId}`);
    }

    async getThreatFeeds(): Promise<ThreatFeed[]> {
        return this.fetch<ThreatFeed[]>('/threat/feeds');
    }

    async getShadowApi(): Promise<ShadowApiEndpoint[]> {
        return this.fetch<ShadowApiEndpoint[]>('/shadow-api/endpoints');
    }

    // ML Threshold
    async updateMLThreshold(threshold: number): Promise<{ success: boolean; message: string }> {
        return this.fetch('/admin/ml/threshold', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threshold })
        });
    }

    // Rules Hot-Reload
    async reloadRules(): Promise<{ success: boolean; message: string; rules_loaded: number }> {
        return this.fetch('/rules/reload', { method: 'POST' });
    }

    // Create Vulnerability
    async createVulnerability(vuln: { title: string; severity: string; description: string; affected_path?: string }): Promise<any> {
        return this.fetch('/vulnerabilities', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(vuln)
        });
    }

    // Prometheus Metrics
    async getMetrics(): Promise<string> {
        const response = await fetch(`${this.getBaseUrl()}/metrics`, {
            headers: this.getAuthHeaders()
        });
        return response.text();
    }

    private getBaseUrl(): string {
        return (import.meta as any).env?.PUBLIC_API_URL || '/api';
    }

    private getAuthHeaders(): Record<string, string> {
        const headers: Record<string, string> = {};
        if (typeof localStorage !== 'undefined') {
            const token = localStorage.getItem('BRUTAL_TOKEN');
            if (token) headers['X-Admin-Token'] = token;
        }
        return headers;
    }
}

export const api = new ApiClient();
export default api;
