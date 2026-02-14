<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import type { ShadowReport, ShadowApiEndpoint } from "$lib/types";
    import {
        Eye,
        EyeOff,
        Shield,
        ShieldAlert,
        ShieldCheck,
        Zap,
        Rocket,
        Users,
        Activity,
        AlertTriangle,
        BarChart3,
        RefreshCw,
        Settings,
        Globe,
        X,
    } from "lucide-svelte";

    let shadowEnabled = false;
    let report: ShadowReport | null = null;
    let endpoints: ShadowApiEndpoint[] = [];
    let loading = true;
    let toggling = false;
    let promoting = false;
    let refreshing = false;
    let trafficPercentage = 100;

    // Detail panel
    let activeDetail: string | null = null;

    function toggleDetail(id: string) {
        activeDetail = activeDetail === id ? null : id;
    }

    // Toast
    let showToast = false;
    let toastMessage = "";
    let toastType: "success" | "error" | "info" = "success";

    onMount(async () => {
        await loadData();
    });

    async function loadData() {
        loading = true;
        try {
            const [statusRes, reportRes] = await Promise.allSettled([
                api.getShadowStatus(),
                api.getShadowReport(),
            ]);

            if (statusRes.status === "fulfilled") {
                shadowEnabled = statusRes.value?.enabled || false;
            }

            if (reportRes.status === "fulfilled") {
                report = reportRes.value;
            } else {
                report = {
                    total_analyzed: 0,
                    simulated_blocks: 0,
                    top_rules: [],
                    top_ips: [],
                };
            }

            // Try loading shadow API endpoints
            try {
                endpoints = await api.getShadowApi();
            } catch {
                endpoints = [];
            }
        } catch (e) {
            console.error("Failed to load shadow data", e);
            report = {
                total_analyzed: 0,
                simulated_blocks: 0,
                top_rules: [],
                top_ips: [],
            };
        } finally {
            loading = false;
        }
    }

    async function toggleShadow() {
        toggling = true;
        try {
            if (shadowEnabled) {
                await api.disableShadow();
                shadowEnabled = false;
                notify("Shadow Mode disabled", "info");
            } else {
                await api.enableShadow("default", trafficPercentage);
                shadowEnabled = true;
                notify(
                    "Shadow Mode enabled — WAF is now logging threats without blocking",
                    "success",
                );
            }
        } catch (e) {
            console.error("Failed to toggle shadow mode", e);
            notify("Failed to toggle shadow mode", "error");
        } finally {
            toggling = false;
        }
    }

    async function refreshData() {
        refreshing = true;
        await loadData();
        refreshing = false;
        notify("Data refreshed", "info");
    }

    async function promoteToBlock() {
        if (
            !confirm(
                "⚠️ This will disable Shadow Mode and activate BLOCKING for all detected threats. Continue?",
            )
        )
            return;
        promoting = true;
        try {
            await api.promoteShadowToBlock();
            shadowEnabled = false;
            await loadData();
            notify(
                "Promoted to BLOCKING mode — WAF is now actively blocking threats",
                "success",
            );
        } catch (e) {
            console.error("Failed to promote", e);
            notify("Failed to promote to blocking mode", "error");
        } finally {
            promoting = false;
        }
    }

    function notify(
        msg: string,
        type: "success" | "error" | "info" = "success",
    ) {
        toastMessage = msg;
        toastType = type;
        showToast = true;
        setTimeout(() => {
            showToast = false;
        }, 3000);
    }

    $: blockRate =
        report && report.total_analyzed > 0
            ? ((report.simulated_blocks / report.total_analyzed) * 100).toFixed(
                  1,
              )
            : "0.0";

    $: uniqueRules = report?.top_rules?.length || 0;
    $: uniqueIps = report?.top_ips?.length || 0;
</script>

<div class="page">
    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <div class="title-row">
                <div class="icon-circle" class:active={shadowEnabled}>
                    {#if shadowEnabled}
                        <Eye size={24} />
                    {:else}
                        <EyeOff size={24} />
                    {/if}
                </div>
                <div>
                    <h1>Shadow Mode</h1>
                    <p class="subtitle">
                        Monitor threats without blocking — analyze before you
                        enforce
                    </p>
                </div>
            </div>
        </div>
        <div class="header-actions">
            <button
                class="btn-icon"
                on:click={refreshData}
                disabled={refreshing}
            >
                <RefreshCw size={16} class={refreshing ? "spin" : ""} />
            </button>
            {#if shadowEnabled}
                <button
                    class="btn-promote"
                    on:click={promoteToBlock}
                    disabled={promoting}
                >
                    <Rocket size={16} />
                    {promoting ? "Promoting..." : "Promote to Blocking"}
                </button>
            {/if}
        </div>
    </div>

    <!-- Master Toggle Card -->
    <div class="toggle-card" class:enabled={shadowEnabled}>
        <div class="toggle-card-content">
            <div class="toggle-info">
                <div class="toggle-status">
                    <span class="status-dot" class:active={shadowEnabled}
                    ></span>
                    <span class="status-label"
                        >{shadowEnabled ? "ACTIVE" : "INACTIVE"}</span
                    >
                </div>
                <p class="toggle-desc">
                    {#if shadowEnabled}
                        Shadow Mode is <strong>active</strong>. The WAF is
                        monitoring all traffic and recording what <em>would</em>
                        be blocked, without actually blocking any requests.
                    {:else}
                        Shadow Mode is <strong>disabled</strong>. Enable it to
                        start monitoring threats without impacting live traffic.
                    {/if}
                </p>
            </div>
            <button
                class="toggle-switch"
                class:on={shadowEnabled}
                on:click={toggleShadow}
                disabled={toggling}
            >
                <span class="toggle-knob"></span>
            </button>
        </div>

        {#if !shadowEnabled}
            <div class="config-section">
                <div class="config-row">
                    <label class="config-label">
                        <Settings size={14} />
                        Traffic Sampling
                    </label>
                    <div class="slider-group">
                        <input
                            type="range"
                            min="10"
                            max="100"
                            step="10"
                            bind:value={trafficPercentage}
                            class="slider"
                        />
                        <span class="slider-value">{trafficPercentage}%</span>
                    </div>
                </div>
            </div>
        {/if}
    </div>

    <!-- Stats Grid — Clickable -->
    <div class="stats-grid">
        <button
            class="stat-card"
            class:expanded={activeDetail === "analyzed"}
            on:click={() => toggleDetail("analyzed")}
        >
            <div class="stat-header">
                <span class="stat-title">Total Analyzed</span>
                <Activity size={18} class="stat-icon blue" />
            </div>
            <div class="stat-value">
                {report?.total_analyzed?.toLocaleString() || "0"}
            </div>
            <div class="stat-sub">Requests inspected in shadow mode</div>
        </button>

        <button
            class="stat-card threat"
            class:expanded={activeDetail === "simulated"}
            on:click={() => toggleDetail("simulated")}
        >
            <div class="stat-header">
                <span class="stat-title">Simulated Blocks</span>
                <ShieldAlert size={18} class="stat-icon red" />
            </div>
            <div class="stat-value red">
                {report?.simulated_blocks?.toLocaleString() || "0"}
            </div>
            <div class="stat-sub">Would be blocked if active</div>
        </button>

        <button
            class="stat-card"
            class:expanded={activeDetail === "rate"}
            on:click={() => toggleDetail("rate")}
        >
            <div class="stat-header">
                <span class="stat-title">Block Rate</span>
                <BarChart3 size={18} class="stat-icon amber" />
            </div>
            <div class="stat-value amber">{blockRate}%</div>
            <div class="stat-sub">Of total traffic would be blocked</div>
        </button>

        <button
            class="stat-card"
            class:expanded={activeDetail === "rules"}
            on:click={() => toggleDetail("rules")}
        >
            <div class="stat-header">
                <span class="stat-title">Unique Rules</span>
                <Zap size={18} class="stat-icon cyan" />
            </div>
            <div class="stat-value cyan">{uniqueRules}</div>
            <div class="stat-sub">Rules that would trigger</div>
        </button>
    </div>

    <!-- Detail Panel -->
    {#if activeDetail}
        <div class="detail-panel">
            <div class="detail-panel-header">
                <h3>
                    {#if activeDetail === "analyzed"}
                        <Activity size={16} /> Traffic Analysis
                    {:else if activeDetail === "simulated"}
                        <ShieldAlert size={16} /> Simulated Block Details
                    {:else if activeDetail === "rate"}
                        <BarChart3 size={16} /> Block Rate Analysis
                    {:else}
                        <Zap size={16} /> Rule Trigger Details
                    {/if}
                </h3>
                <button
                    class="btn-close-detail"
                    on:click={() => (activeDetail = null)}
                    ><X size={14} /></button
                >
            </div>
            <div class="detail-panel-body">
                <div class="detail-grid">
                    {#if activeDetail === "analyzed"}
                        <div class="detail-item">
                            <span class="detail-label">Total Analyzed</span
                            ><span class="detail-val"
                                >{report?.total_analyzed?.toLocaleString() ||
                                    "0"}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Would Be Blocked</span
                            ><span class="detail-val red"
                                >{report?.simulated_blocks?.toLocaleString() ||
                                    "0"}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Would Pass</span><span
                                class="detail-val green"
                                >{(
                                    (report?.total_analyzed || 0) -
                                    (report?.simulated_blocks || 0)
                                ).toLocaleString()}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Mode</span><span
                                class="detail-val"
                                >{shadowEnabled ? "Active" : "Disabled"}</span
                            >
                        </div>
                    {:else if activeDetail === "simulated"}
                        <div class="detail-item">
                            <span class="detail-label">Simulated Blocks</span
                            ><span class="detail-val red"
                                >{report?.simulated_blocks?.toLocaleString() ||
                                    "0"}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Unique Rules</span><span
                                class="detail-val">{uniqueRules}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Unique IPs</span><span
                                class="detail-val">{uniqueIps}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Block Rate</span><span
                                class="detail-val amber">{blockRate}%</span
                            >
                        </div>
                    {:else if activeDetail === "rate"}
                        <div class="detail-item">
                            <span class="detail-label">Block Rate</span><span
                                class="detail-val amber">{blockRate}%</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Pass Rate</span><span
                                class="detail-val green"
                                >{(100 - parseFloat(blockRate)).toFixed(
                                    1,
                                )}%</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Total Analyzed</span
                            ><span class="detail-val"
                                >{report?.total_analyzed?.toLocaleString() ||
                                    "0"}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Sampling</span><span
                                class="detail-val">{trafficPercentage}%</span
                            >
                        </div>
                    {:else}
                        <div class="detail-item">
                            <span class="detail-label">Unique Rules</span><span
                                class="detail-val cyan">{uniqueRules}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Total Triggers</span
                            ><span class="detail-val"
                                >{report?.simulated_blocks?.toLocaleString() ||
                                    "0"}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Top Rules</span><span
                                class="detail-val"
                                >{report?.top_rules?.length || 0}</span
                            >
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Top IPs</span><span
                                class="detail-val"
                                >{report?.top_ips?.length || 0}</span
                            >
                        </div>
                    {/if}
                </div>
            </div>
        </div>
    {/if}

    <!-- Two Column Layout -->
    <div class="two-col">
        <!-- Top Rules -->
        <div class="panel">
            <div class="panel-header">
                <ShieldCheck size={18} />
                <h3>Top Rules That Would Block</h3>
            </div>
            <div class="panel-body">
                {#if report?.top_rules && report.top_rules.length > 0}
                    <div class="list">
                        {#each report.top_rules as rule}
                            <div class="list-item">
                                <div class="list-item-info">
                                    <span class="rule-id"
                                        >{rule.rule_id || "—"}</span
                                    >
                                    <span class="rule-desc"
                                        >Rule #{rule.rule_id}</span
                                    >
                                </div>
                                <span class="badge count">{rule.count}</span>
                            </div>
                        {/each}
                    </div>
                {:else}
                    <div class="empty-state">
                        <ShieldCheck size={32} class="empty-icon" />
                        <p>No shadow blocks recorded yet</p>
                        <p class="empty-hint">
                            {shadowEnabled
                                ? "Monitoring active — data will appear as traffic flows"
                                : "Enable Shadow Mode to start monitoring"}
                        </p>
                    </div>
                {/if}
            </div>
        </div>

        <!-- Top IPs -->
        <div class="panel">
            <div class="panel-header">
                <Users size={18} />
                <h3>Top IPs That Would Be Blocked</h3>
            </div>
            <div class="panel-body">
                {#if report?.top_ips && report.top_ips.length > 0}
                    <div class="list">
                        {#each report.top_ips as ip}
                            <div class="list-item">
                                <div class="list-item-info">
                                    <Globe size={14} class="ip-icon" />
                                    <span class="ip-addr">{ip.ip || "—"}</span>
                                </div>
                                <span class="badge count">{ip.count}</span>
                            </div>
                        {/each}
                    </div>
                {:else}
                    <div class="empty-state">
                        <Users size={32} class="empty-icon" />
                        <p>No IP data recorded yet</p>
                        <p class="empty-hint">
                            {shadowEnabled
                                ? "Monitoring active — IPs will appear soon"
                                : "Enable Shadow Mode to start tracking"}
                        </p>
                    </div>
                {/if}
            </div>
        </div>
    </div>

    <!-- Discovered Endpoints -->
    <div class="panel full-width">
        <div class="panel-header">
            <Globe size={18} />
            <h3>Discovered Shadow Endpoints</h3>
            <span class="badge outline">{endpoints.length}</span>
        </div>
        <div class="panel-body">
            {#if endpoints.length > 0}
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Method</th>
                                <th>Path</th>
                                <th>Risk Score</th>
                                <th>Discovered</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each endpoints as ep}
                                <tr>
                                    <td
                                        ><span
                                            class="method-badge {(
                                                ep.method || 'GET'
                                            ).toLowerCase()}"
                                            >{ep.method || "GET"}</span
                                        ></td
                                    >
                                    <td class="mono">{ep.path || "/"}</td>
                                    <td>
                                        <span
                                            class="risk-badge"
                                            class:high={ep.risk_score >= 7}
                                            class:medium={ep.risk_score >= 4 &&
                                                ep.risk_score < 7}
                                            class:low={ep.risk_score < 4}
                                        >
                                            {ep.risk_score || 0}
                                        </span>
                                    </td>
                                    <td class="text-muted"
                                        >{ep.discovered_at || "—"}</td
                                    >
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            {:else}
                <div class="empty-state">
                    <Globe size={32} class="empty-icon" />
                    <p>No endpoints discovered yet</p>
                    <p class="empty-hint">
                        Shadow mode will automatically discover API endpoints as
                        traffic flows through the WAF
                    </p>
                </div>
            {/if}
        </div>
    </div>
</div>

<!-- Toast -->
{#if showToast}
    <div class="toast {toastType}">
        {#if toastType === "success"}
            <ShieldCheck size={16} />
        {:else if toastType === "error"}
            <AlertTriangle size={16} />
        {:else}
            <Activity size={16} />
        {/if}
        <span>{toastMessage}</span>
    </div>
{/if}

<style>
    .page {
        max-width: 1200px;
        margin: 0 auto;
        padding: 2rem 1.5rem;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
    }

    /* Header */
    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }
    .title-row {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .icon-circle {
        width: 48px;
        height: 48px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #1a1a2e;
        color: #666;
        border: 1px solid #222;
        transition: all 0.3s;
    }
    .icon-circle.active {
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
        color: white;
        border-color: transparent;
        box-shadow: 0 0 20px rgba(14, 165, 233, 0.3);
    }
    h1 {
        font-size: 1.75rem;
        font-weight: 800;
        color: white;
        margin: 0;
    }
    .subtitle {
        color: #666;
        margin: 0.25rem 0 0;
        font-size: 0.875rem;
    }
    .header-actions {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    .btn-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        border: 1px solid #333;
        background: #111;
        color: #888;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
    }
    .btn-icon:hover {
        border-color: #555;
        color: white;
    }
    .btn-promote {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: 1px solid #f59e0b33;
        background: linear-gradient(135deg, #f59e0b22, #ef444422);
        color: #f59e0b;
        font-weight: 600;
        font-size: 0.8125rem;
        cursor: pointer;
        transition: all 0.2s;
    }
    .btn-promote:hover {
        background: linear-gradient(135deg, #f59e0b33, #ef444433);
        border-color: #f59e0b55;
    }
    .btn-promote:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    /* Toggle Card */
    .toggle-card {
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 16px;
        padding: 1.5rem;
        transition: all 0.3s;
    }
    .toggle-card.enabled {
        border-color: #0ea5e933;
        box-shadow: 0 0 30px rgba(14, 165, 233, 0.05);
    }
    .toggle-card-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 2rem;
    }
    .toggle-info {
        flex: 1;
    }
    .toggle-status {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }
    .status-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #666;
        transition: all 0.3s;
    }
    .status-dot.active {
        background: #0ea5e9;
        box-shadow: 0 0 8px #0ea5e9;
    }
    .status-label {
        font-size: 0.6875rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        color: #777;
    }
    .toggle-desc {
        color: #888;
        font-size: 0.875rem;
        margin: 0;
        line-height: 1.5;
    }
    .toggle-desc strong {
        color: #ccc;
    }

    /* Toggle Switch */
    .toggle-switch {
        width: 56px;
        height: 30px;
        border-radius: 15px;
        border: none;
        background: #222;
        cursor: pointer;
        position: relative;
        flex-shrink: 0;
        transition: background 0.3s;
    }
    .toggle-switch.on {
        background: linear-gradient(135deg, #0ea5e9, #6366f1);
    }
    .toggle-switch:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .toggle-knob {
        position: absolute;
        top: 3px;
        left: 3px;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        background: white;
        transition: transform 0.3s ease;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    .toggle-switch.on .toggle-knob {
        transform: translateX(26px);
    }

    /* Config Section */
    .config-section {
        margin-top: 1.25rem;
        padding-top: 1.25rem;
        border-top: 1px solid #1a1a2e;
    }
    .config-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    .config-label {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: #888;
        font-size: 0.8125rem;
        font-weight: 500;
    }
    .slider-group {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .slider {
        width: 200px;
        height: 4px;
        -webkit-appearance: none;
        appearance: none;
        background: #222;
        border-radius: 2px;
        outline: none;
    }
    .slider::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 16px;
        height: 16px;
        border-radius: 50%;
        background: #0ea5e9;
        cursor: pointer;
        box-shadow: 0 0 8px rgba(14, 165, 233, 0.4);
    }
    .slider-value {
        font-family: "JetBrains Mono", "Fira Code", monospace;
        font-size: 0.8125rem;
        color: #0ea5e9;
        min-width: 3rem;
        text-align: right;
    }

    /* Stats Grid */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
    }
    .stat-card {
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        padding: 1.25rem;
        cursor: pointer;
        transition: all 0.2s;
        text-align: left;
        color: inherit;
        font-family: inherit;
        width: 100%;
    }
    .stat-card:hover {
        border-color: #2a2a3e;
    }
    .stat-card.expanded {
        border-color: #0ea5e944;
        background: #0a0a14;
    }
    .stat-card.threat {
        border-color: #ef444433;
    }
    .stat-card.threat.expanded {
        border-color: #ef444466;
    }

    /* Detail Panel */
    .detail-panel {
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        overflow: hidden;
        animation: slideDown 0.2s ease;
    }
    .detail-panel-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.875rem 1.25rem;
        border-bottom: 1px solid #1a1a2e;
    }
    .detail-panel-header h3 {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.8125rem;
        font-weight: 600;
        color: #ccc;
        margin: 0;
    }
    .btn-close-detail {
        width: 28px;
        height: 28px;
        border-radius: 6px;
        border: 1px solid #333;
        background: transparent;
        color: #666;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.15s;
    }
    .btn-close-detail:hover {
        background: #1a1a2e;
        color: white;
    }
    .detail-panel-body {
        padding: 1.25rem;
    }
    .detail-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1rem;
    }
    .detail-item {
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
    }
    .detail-label {
        font-size: 0.6875rem;
        color: #555;
        font-weight: 500;
    }
    .detail-val {
        font-size: 1.125rem;
        font-weight: 700;
        color: white;
        font-family: "JetBrains Mono", monospace;
    }
    .detail-val.red {
        color: #ef4444;
    }
    .detail-val.green {
        color: #10b981;
    }
    .detail-val.amber {
        color: #f59e0b;
    }
    .detail-val.cyan {
        color: #0ea5e9;
    }
    @keyframes slideDown {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    .stat-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.75rem;
    }
    .stat-title {
        font-size: 0.75rem;
        font-weight: 500;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .stat-value {
        font-size: 2rem;
        font-weight: 800;
        color: white;
        font-family: "JetBrains Mono", "Fira Code", monospace;
        line-height: 1;
        margin-bottom: 0.5rem;
    }
    .stat-value.red {
        color: #ef4444;
    }
    .stat-value.amber {
        color: #f59e0b;
    }
    .stat-value.cyan {
        color: #0ea5e9;
    }
    .stat-sub {
        font-size: 0.6875rem;
        color: #555;
    }

    :global(.stat-icon.blue) {
        color: #3b82f6;
    }
    :global(.stat-icon.red) {
        color: #ef4444;
    }
    :global(.stat-icon.amber) {
        color: #f59e0b;
    }
    :global(.stat-icon.cyan) {
        color: #0ea5e9;
    }

    /* Panels */
    .two-col {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1rem;
    }
    .panel {
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        overflow: hidden;
    }
    .panel.full-width {
        grid-column: 1 / -1;
    }
    .panel-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 1rem 1.25rem;
        border-bottom: 1px solid #1a1a2e;
        color: #ccc;
    }
    .panel-header h3 {
        font-size: 0.875rem;
        font-weight: 600;
        margin: 0;
        flex: 1;
    }
    .panel-body {
        padding: 0;
    }

    /* Lists */
    .list-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 1.25rem;
        border-bottom: 1px solid #0f0f17;
        transition: background 0.15s;
    }
    .list-item:last-child {
        border-bottom: none;
    }
    .list-item:hover {
        background: #111118;
    }
    .list-item-info {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    .rule-id {
        font-family: "JetBrains Mono", monospace;
        font-size: 0.75rem;
        color: #0ea5e9;
        background: #0ea5e910;
        padding: 0.125rem 0.5rem;
        border-radius: 4px;
    }
    .rule-desc {
        color: #888;
        font-size: 0.8125rem;
    }
    :global(.ip-icon) {
        color: #555;
    }
    .ip-addr {
        font-family: "JetBrains Mono", monospace;
        font-size: 0.8125rem;
        color: #ccc;
    }
    .badge {
        font-size: 0.6875rem;
        font-weight: 600;
        padding: 0.125rem 0.5rem;
        border-radius: 6px;
    }
    .badge.count {
        background: #ffffff0a;
        color: #888;
        font-family: "JetBrains Mono", monospace;
    }
    .badge.outline {
        border: 1px solid #333;
        color: #666;
    }

    /* Empty state */
    .empty-state {
        padding: 3rem 1.5rem;
        text-align: center;
        color: #555;
    }
    :global(.empty-icon) {
        color: #333;
        margin-bottom: 1rem;
    }
    .empty-state p {
        margin: 0.25rem 0;
    }
    .empty-hint {
        font-size: 0.75rem;
        color: #444;
    }

    /* Table */
    .table-wrap {
        overflow-x: auto;
    }
    table {
        width: 100%;
        border-collapse: collapse;
    }
    th {
        text-align: left;
        padding: 0.75rem 1.25rem;
        font-size: 0.6875rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #555;
        background: #08080d;
    }
    td {
        padding: 0.75rem 1.25rem;
        font-size: 0.8125rem;
        border-top: 1px solid #0f0f17;
    }
    .mono {
        font-family: "JetBrains Mono", monospace;
        color: #ccc;
    }
    .text-muted {
        color: #555;
        font-size: 0.75rem;
    }
    .method-badge {
        font-size: 0.625rem;
        font-weight: 700;
        padding: 0.125rem 0.375rem;
        border-radius: 3px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .method-badge.get {
        background: #10b98110;
        color: #10b981;
    }
    .method-badge.post {
        background: #3b82f610;
        color: #3b82f6;
    }
    .method-badge.put {
        background: #f59e0b10;
        color: #f59e0b;
    }
    .method-badge.delete {
        background: #ef444410;
        color: #ef4444;
    }
    .risk-badge {
        font-size: 0.6875rem;
        font-weight: 700;
        padding: 0.125rem 0.5rem;
        border-radius: 4px;
        font-family: "JetBrains Mono", monospace;
    }
    .risk-badge.high {
        background: #ef444415;
        color: #ef4444;
    }
    .risk-badge.medium {
        background: #f59e0b15;
        color: #f59e0b;
    }
    .risk-badge.low {
        background: #10b98115;
        color: #10b981;
    }

    /* Toast */
    .toast {
        position: fixed;
        bottom: 2rem;
        left: 50%;
        transform: translateX(-50%);
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.75rem 1.25rem;
        border-radius: 999px;
        font-size: 0.8125rem;
        font-weight: 500;
        z-index: 60;
        background: #111;
        border: 1px solid #333;
        color: white;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5);
        animation: slideUp 0.3s ease;
    }
    .toast.success {
        border-color: #10b98133;
    }
    .toast.error {
        border-color: #ef444433;
    }
    .toast.info {
        border-color: #3b82f633;
    }

    :global(.spin) {
        animation: spin 1s linear infinite;
    }

    @keyframes spin {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }

    @keyframes slideUp {
        from {
            transform: translateX(-50%) translateY(20px);
            opacity: 0;
        }
        to {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }
    }

    @media (max-width: 768px) {
        .stats-grid {
            grid-template-columns: repeat(2, 1fr);
        }
        .two-col {
            grid-template-columns: 1fr;
        }
        .toggle-card-content {
            flex-direction: column;
            align-items: stretch;
        }
    }
</style>
