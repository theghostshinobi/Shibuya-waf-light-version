<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { api } from "$lib/api/client";
    import {
        Bot,
        Shield,
        Cpu,
        Activity,
        Settings,
        Save,
        Zap,
        ShieldAlert,
        Brain,
        X,
        AlertTriangle,
        ShieldCheck,
        RefreshCw,
    } from "lucide-svelte";

    interface BotStats {
        total_requests_analyzed: number;
        bots_detected: number;
        bots_blocked: number;
        fingerprint_matches: number;
        behavior_score_blocks: number;
    }

    interface BotConfig {
        enabled: boolean;
        fingerprint_check: boolean;
        behavior_analysis: boolean;
        block_threshold: number;
    }

    let stats: BotStats = {
        total_requests_analyzed: 0,
        bots_detected: 0,
        bots_blocked: 0,
        fingerprint_matches: 0,
        behavior_score_blocks: 0,
    };

    let config: BotConfig = {
        enabled: true,
        fingerprint_check: true,
        behavior_analysis: true,
        block_threshold: 0.8,
    };

    let loading = true;
    let saving = false;
    let refreshing = false;
    let interval: any;

    // Detail panel
    let activeDetail: string | null = null;

    // Toast
    let showToast = false;
    let toastMessage = "";
    let toastType: "success" | "error" | "info" = "success";

    onMount(async () => {
        await loadData();
        interval = setInterval(loadStats, 5000);
    });

    onDestroy(() => {
        if (interval) clearInterval(interval);
    });

    async function loadData() {
        loading = true;
        try {
            await Promise.all([loadStats(), loadConfig()]);
        } catch (err) {
            notify("Failed to synchronize with Shibuya core", "error");
        } finally {
            loading = false;
        }
    }

    async function loadStats() {
        try {
            stats = await api.getBotDetectionStats();
        } catch (err) {
            console.error("Failed to load bot stats:", err);
        }
    }

    async function loadConfig() {
        try {
            config = await api.getBotDetectionConfig();
        } catch (err) {
            console.error("Failed to load bot config:", err);
        }
    }

    async function saveConfig() {
        saving = true;
        try {
            await api.updateBotDetectionConfig(config);
            notify("Configuration saved successfully", "success");
        } catch (err) {
            notify("Failed to update detection parameters", "error");
        } finally {
            saving = false;
        }
    }

    async function toggleEnabled() {
        config.enabled = !config.enabled;
        await saveConfig();
    }

    async function toggleFingerprint() {
        config.fingerprint_check = !config.fingerprint_check;
        await saveConfig();
    }

    async function toggleBehavior() {
        config.behavior_analysis = !config.behavior_analysis;
        await saveConfig();
    }

    async function refreshData() {
        refreshing = true;
        await loadData();
        refreshing = false;
        notify("Data refreshed", "info");
    }

    function toggleDetail(id: string) {
        activeDetail = activeDetail === id ? null : id;
    }

    function notify(msg: string, type: "success" | "error" | "info") {
        toastMessage = msg;
        toastType = type;
        showToast = true;
        setTimeout(() => {
            showToast = false;
        }, 3000);
    }

    $: detectionRate =
        stats.total_requests_analyzed > 0
            ? (
                  (stats.bots_detected / stats.total_requests_analyzed) *
                  100
              ).toFixed(1)
            : "0.0";

    $: blockRate =
        stats.bots_detected > 0
            ? ((stats.bots_blocked / stats.bots_detected) * 100).toFixed(1)
            : "0.0";

    $: thresholdPercent = (config.block_threshold * 100).toFixed(0);
</script>

<div class="page">
    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <div class="title-row">
                <div class="icon-circle" class:active={config.enabled}>
                    <Bot size={24} />
                </div>
                <div>
                    <h1>Bot Detection</h1>
                    <p class="subtitle">
                        Behavioral analysis & fingerprinting — real-time
                        automated threat mitigation
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
            <div class="engine-status" class:active={config.enabled}>
                <span class="status-dot"></span>
                {config.enabled ? "Active Monitoring" : "Protection Disabled"}
            </div>
        </div>
    </div>

    {#if loading}
        <div class="stats-grid">
            {#each [1, 2, 3, 4, 5] as _}
                <div class="stat-card skeleton"></div>
            {/each}
        </div>
    {:else}
        <!-- Stats Grid — Clickable cards -->
        <div class="stats-grid">
            <button
                class="stat-card"
                class:expanded={activeDetail === "analyzed"}
                on:click={() => toggleDetail("analyzed")}
            >
                <div class="stat-icon-bg blue"><Activity size={18} /></div>
                <div class="stat-content">
                    <span class="stat-label">Traffic Analyzed</span>
                    <span class="stat-value"
                        >{stats.total_requests_analyzed.toLocaleString()}</span
                    >
                    <span class="stat-sub blue">Real-time inspection</span>
                </div>
            </button>

            <button
                class="stat-card"
                class:expanded={activeDetail === "flagged"}
                on:click={() => toggleDetail("flagged")}
            >
                <div class="stat-icon-bg amber"><ShieldAlert size={18} /></div>
                <div class="stat-content">
                    <span class="stat-label">Bots Flagged</span>
                    <span class="stat-value amber"
                        >{stats.bots_detected.toLocaleString()}</span
                    >
                    <span class="stat-sub">{detectionRate}% of traffic</span>
                </div>
            </button>

            <button
                class="stat-card"
                class:expanded={activeDetail === "blocked"}
                on:click={() => toggleDetail("blocked")}
            >
                <div class="stat-icon-bg red"><Shield size={18} /></div>
                <div class="stat-content">
                    <span class="stat-label">Threats Mitigated</span>
                    <span class="stat-value red"
                        >{stats.bots_blocked.toLocaleString()}</span
                    >
                    <span class="stat-sub red">{blockRate}% effectiveness</span>
                </div>
            </button>

            <button
                class="stat-card"
                class:expanded={activeDetail === "fingerprint"}
                on:click={() => toggleDetail("fingerprint")}
            >
                <div class="stat-icon-bg violet"><Cpu size={18} /></div>
                <div class="stat-content">
                    <span class="stat-label">Fingerprint Matches</span>
                    <span class="stat-value violet"
                        >{stats.fingerprint_matches.toLocaleString()}</span
                    >
                    <span class="stat-sub">Signature database</span>
                </div>
            </button>

            <button
                class="stat-card"
                class:expanded={activeDetail === "behavior"}
                on:click={() => toggleDetail("behavior")}
            >
                <div class="stat-icon-bg cyan"><Brain size={18} /></div>
                <div class="stat-content">
                    <span class="stat-label">Behavior Scores</span>
                    <span class="stat-value cyan"
                        >{stats.behavior_score_blocks.toLocaleString()}</span
                    >
                    <span class="stat-sub">Probabilistic blocks</span>
                </div>
            </button>
        </div>

        <!-- Detail Panel (expands when a stat card is clicked) -->
        {#if activeDetail}
            <div class="detail-panel">
                <div class="detail-header">
                    <h3>
                        {#if activeDetail === "analyzed"}
                            <Activity size={16} /> Traffic Analysis Details
                        {:else if activeDetail === "flagged"}
                            <ShieldAlert size={16} /> Bot Detection Details
                        {:else if activeDetail === "blocked"}
                            <Shield size={16} /> Mitigation Details
                        {:else if activeDetail === "fingerprint"}
                            <Cpu size={16} /> Fingerprint Match Details
                        {:else}
                            <Brain size={16} /> Behavioral Analysis Details
                        {/if}
                    </h3>
                    <button
                        class="btn-close"
                        on:click={() => (activeDetail = null)}
                        ><X size={14} /></button
                    >
                </div>
                <div class="detail-body">
                    {#if activeDetail === "analyzed"}
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label"
                                    >Total Requests Inspected</span
                                >
                                <span class="detail-val"
                                    >{stats.total_requests_analyzed.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Detection Rate</span>
                                <span class="detail-val">{detectionRate}%</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Clean Traffic</span>
                                <span class="detail-val green"
                                    >{(
                                        stats.total_requests_analyzed -
                                        stats.bots_detected
                                    ).toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Analysis Engine</span
                                >
                                <span class="detail-val"
                                    >{config.enabled
                                        ? "Active"
                                        : "Disabled"}</span
                                >
                            </div>
                        </div>
                    {:else if activeDetail === "flagged"}
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Bots Detected</span>
                                <span class="detail-val amber"
                                    >{stats.bots_detected.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Via Fingerprint</span
                                >
                                <span class="detail-val"
                                    >{stats.fingerprint_matches.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Via Behavior</span>
                                <span class="detail-val"
                                    >{stats.behavior_score_blocks.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Detection %</span>
                                <span class="detail-val">{detectionRate}%</span>
                            </div>
                        </div>
                    {:else if activeDetail === "blocked"}
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Bots Blocked</span>
                                <span class="detail-val red"
                                    >{stats.bots_blocked.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label"
                                    >Block Effectiveness</span
                                >
                                <span class="detail-val">{blockRate}%</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Unblocked Bots</span>
                                <span class="detail-val amber"
                                    >{(
                                        stats.bots_detected - stats.bots_blocked
                                    ).toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Threshold</span>
                                <span class="detail-val"
                                    >{thresholdPercent}%</span
                                >
                            </div>
                        </div>
                    {:else if activeDetail === "fingerprint"}
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label"
                                    >Fingerprint Matches</span
                                >
                                <span class="detail-val violet"
                                    >{stats.fingerprint_matches.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Engine Status</span>
                                <span class="detail-val"
                                    >{config.fingerprint_check
                                        ? "Active"
                                        : "Disabled"}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">% of Detections</span
                                >
                                <span class="detail-val"
                                    >{stats.bots_detected > 0
                                        ? (
                                              (stats.fingerprint_matches /
                                                  stats.bots_detected) *
                                              100
                                          ).toFixed(1)
                                        : "0.0"}%</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Method</span>
                                <span class="detail-val"
                                    >User-Agent, JA3, HTTP/2</span
                                >
                            </div>
                        </div>
                    {:else}
                        <div class="detail-grid">
                            <div class="detail-item">
                                <span class="detail-label">Behavior Blocks</span
                                >
                                <span class="detail-val cyan"
                                    >{stats.behavior_score_blocks.toLocaleString()}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Engine Status</span>
                                <span class="detail-val"
                                    >{config.behavior_analysis
                                        ? "Active"
                                        : "Disabled"}</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">% of Detections</span
                                >
                                <span class="detail-val"
                                    >{stats.bots_detected > 0
                                        ? (
                                              (stats.behavior_score_blocks /
                                                  stats.bots_detected) *
                                              100
                                          ).toFixed(1)
                                        : "0.0"}%</span
                                >
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Method</span>
                                <span class="detail-val"
                                    >ML Scoring, Entropy</span
                                >
                            </div>
                        </div>
                    {/if}
                </div>
            </div>
        {/if}

        <!-- Controls -->
        <div class="controls-grid">
            <!-- Configuration Panel -->
            <div class="config-panel">
                <div class="config-header">
                    <div class="config-title">
                        <Settings size={16} />
                        <span>Detection Parameters</span>
                    </div>
                    <button
                        class="btn-save"
                        on:click={saveConfig}
                        disabled={saving}
                    >
                        {#if saving}
                            Saving...
                        {:else}
                            <Save size={14} /> Apply Changes
                        {/if}
                    </button>
                </div>

                <div class="config-body">
                    <!-- Master Toggle -->
                    <div class="config-item master">
                        <div class="config-item-left">
                            <div class="config-icon blue">
                                <Zap size={18} />
                            </div>
                            <div>
                                <span class="config-name"
                                    >Global Bot Mitigation</span
                                >
                                <span class="config-desc"
                                    >Master orchestration for all detection
                                    vectors</span
                                >
                            </div>
                        </div>
                        <button
                            class="toggle-switch"
                            class:on={config.enabled}
                            on:click={toggleEnabled}
                        >
                            <span class="toggle-knob"></span>
                        </button>
                    </div>

                    <div
                        class="config-sub-grid"
                        class:disabled={!config.enabled}
                    >
                        <!-- Fingerprint Toggle -->
                        <div class="config-item sub">
                            <div class="config-item-left">
                                <Cpu size={14} class="text-violet" />
                                <div>
                                    <span class="config-name"
                                        >Signature Match</span
                                    >
                                    <span class="config-desc"
                                        >Cross-reference HTTP/TLS headers
                                        against known non-human patterns</span
                                    >
                                </div>
                            </div>
                            <button
                                class="toggle-switch sm"
                                class:on={config.fingerprint_check}
                                on:click={toggleFingerprint}
                                disabled={!config.enabled}
                            >
                                <span class="toggle-knob"></span>
                            </button>
                        </div>

                        <!-- Behavior Toggle -->
                        <div class="config-item sub">
                            <div class="config-item-left">
                                <Brain size={14} class="text-cyan" />
                                <div>
                                    <span class="config-name"
                                        >Heuristic Engine</span
                                    >
                                    <span class="config-desc"
                                        >Identify scrapers and crawlers via
                                        request frequency and path traversal</span
                                    >
                                </div>
                            </div>
                            <button
                                class="toggle-switch sm"
                                class:on={config.behavior_analysis}
                                on:click={toggleBehavior}
                                disabled={!config.enabled}
                            >
                                <span class="toggle-knob"></span>
                            </button>
                        </div>
                    </div>

                    <!-- Threshold Slider -->
                    <div
                        class="threshold-section"
                        class:disabled={!config.enabled}
                    >
                        <div class="threshold-header">
                            <div>
                                <span class="config-name"
                                    >Mitigation Threshold</span
                                >
                                <span class="config-desc"
                                    >Block requests exceeding this confidence
                                    level</span
                                >
                            </div>
                            <span class="threshold-value"
                                >{thresholdPercent}%</span
                            >
                        </div>
                        <input
                            type="range"
                            min="0"
                            max="1"
                            step="0.01"
                            bind:value={config.block_threshold}
                            class="slider"
                            disabled={!config.enabled}
                        />
                        <div class="slider-labels">
                            <span>Permissive (0%)</span>
                            <span>Balanced</span>
                            <span>Strict (100%)</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Info Sidebar -->
            <div class="info-sidebar">
                <div class="insight-card">
                    <div class="insight-header">
                        <Activity size={16} />
                        <span>Live Insight</span>
                    </div>
                    <p>
                        Currently identifying <strong
                            >{stats.bots_detected}</strong
                        > unique automated patterns. Targeted mitigation is active
                        at the edge.
                    </p>
                </div>

                <div class="logic-card">
                    <h4><Settings size={14} /> Mitigation Logic</h4>
                    <div class="logic-item blue">
                        <span class="logic-title">Static Check</span>
                        <span class="logic-desc"
                            >Verify User-Agent, JA3 TLS Fingerprints, and HTTP/2
                            Frame orchestration against Shibuya's global threat
                            database.</span
                        >
                    </div>
                    <div class="logic-item cyan">
                        <span class="logic-title">Behavioral Scoring</span>
                        <span class="logic-desc"
                            >Machine learning analysis of request intervals and
                            entropy. Detects "Low & Slow" scrapers and complex
                            automated browsing.</span
                        >
                    </div>
                    <div class="logic-item red">
                        <span class="logic-title">JS Challenges</span>
                        <span class="logic-desc"
                            >Requests between 0.4 and 0.8 bot score are served a
                            non-interactive JS challenge to verify browser
                            legitimacy.</span
                        >
                    </div>
                </div>
            </div>
        </div>
    {/if}
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
        background: linear-gradient(135deg, #3b82f6, #6366f1);
        color: white;
        border-color: transparent;
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
        font-size: 0.8125rem;
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
    .engine-status {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.6875rem;
        font-weight: 600;
        color: #ef4444;
    }
    .engine-status.active {
        color: #10b981;
    }
    .engine-status .status-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: currentColor;
    }
    .engine-status.active .status-dot {
        animation: pulse 2s ease infinite;
    }

    /* Stats Grid */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 0.75rem;
    }
    .stat-card {
        background: #0f0f17;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        padding: 1rem;
        display: flex;
        align-items: flex-start;
        gap: 0.75rem;
        cursor: pointer;
        transition: all 0.2s;
        text-align: left;
        color: inherit;
        font-family: inherit;
    }
    .stat-card:hover {
        border-color: #2a2a3e;
    }
    .stat-card.expanded {
        border-color: #3b82f655;
        background: #0f0f1a;
    }
    .stat-card.skeleton {
        height: 80px;
        animation: pulse 1.5s ease infinite;
        cursor: default;
    }
    .stat-icon-bg {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }
    .stat-icon-bg.blue {
        background: #3b82f615;
        color: #3b82f6;
    }
    .stat-icon-bg.amber {
        background: #f59e0b15;
        color: #f59e0b;
    }
    .stat-icon-bg.red {
        background: #ef444415;
        color: #ef4444;
    }
    .stat-icon-bg.violet {
        background: #8b5cf615;
        color: #8b5cf6;
    }
    .stat-icon-bg.cyan {
        background: #06b6d415;
        color: #06b6d4;
    }
    .stat-content {
        display: flex;
        flex-direction: column;
        gap: 0.125rem;
        min-width: 0;
    }
    .stat-label {
        font-size: 0.625rem;
        color: #555;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 600;
    }
    .stat-value {
        font-size: 1.25rem;
        font-weight: 800;
        color: white;
        font-family: "JetBrains Mono", monospace;
    }
    .stat-value.amber {
        color: #f59e0b;
    }
    .stat-value.red {
        color: #ef4444;
    }
    .stat-value.violet {
        color: #8b5cf6;
    }
    .stat-value.cyan {
        color: #06b6d4;
    }
    .stat-sub {
        font-size: 0.625rem;
        color: #444;
    }
    .stat-sub.blue {
        color: #3b82f6aa;
    }
    .stat-sub.red {
        color: #ef4444aa;
    }

    /* Detail Panel */
    .detail-panel {
        background: #0a0a12;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        overflow: hidden;
        animation: slideDown 0.2s ease;
    }
    .detail-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.875rem 1.25rem;
        border-bottom: 1px solid #1a1a2e;
    }
    .detail-header h3 {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.8125rem;
        font-weight: 600;
        color: #ccc;
        margin: 0;
    }
    .btn-close {
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
    .btn-close:hover {
        background: #1a1a2e;
        color: white;
    }
    .detail-body {
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
    .detail-val.amber {
        color: #f59e0b;
    }
    .detail-val.red {
        color: #ef4444;
    }
    .detail-val.green {
        color: #10b981;
    }
    .detail-val.violet {
        color: #8b5cf6;
    }
    .detail-val.cyan {
        color: #06b6d4;
    }

    /* Controls Grid */
    .controls-grid {
        display: grid;
        grid-template-columns: 2fr 1fr;
        gap: 1rem;
    }
    .config-panel {
        background: #0f0f17;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        overflow: hidden;
    }
    .config-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 1.25rem;
        border-bottom: 1px solid #1a1a2e;
    }
    .config-title {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.875rem;
        font-weight: 600;
        color: #ccc;
    }
    .btn-save {
        display: flex;
        align-items: center;
        gap: 0.375rem;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: none;
        background: #3b82f6;
        color: white;
        font-weight: 600;
        font-size: 0.75rem;
        cursor: pointer;
        transition: all 0.2s;
    }
    .btn-save:hover {
        background: #2563eb;
    }
    .btn-save:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .config-body {
        padding: 1.25rem;
        display: flex;
        flex-direction: column;
        gap: 1rem;
    }

    .config-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem;
        background: #0a0a12;
        border: 1px solid #1a1a2e;
        border-radius: 10px;
    }
    .config-item.master {
        padding: 1.25rem;
    }
    .config-item-left {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    .config-icon {
        width: 40px;
        height: 40px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .config-icon.blue {
        background: #3b82f615;
        color: #3b82f6;
    }
    .config-name {
        display: block;
        font-size: 0.8125rem;
        font-weight: 600;
        color: #ddd;
    }
    .config-desc {
        display: block;
        font-size: 0.6875rem;
        color: #555;
        margin-top: 0.125rem;
    }
    :global(.text-violet) {
        color: #8b5cf6;
    }
    :global(.text-cyan) {
        color: #06b6d4;
    }

    .config-sub-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 0.75rem;
        transition: opacity 0.2s;
    }
    .config-sub-grid.disabled {
        opacity: 0.4;
        pointer-events: none;
    }
    .config-item.sub {
        padding: 0.875rem;
    }

    /* Toggle Switch */
    .toggle-switch {
        width: 48px;
        height: 26px;
        border-radius: 13px;
        border: none;
        background: #222;
        cursor: pointer;
        position: relative;
        flex-shrink: 0;
        transition: background 0.3s;
    }
    .toggle-switch.sm {
        width: 40px;
        height: 22px;
        border-radius: 11px;
    }
    .toggle-switch.on {
        background: linear-gradient(135deg, #3b82f6, #6366f1);
    }
    .toggle-switch:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .toggle-knob {
        position: absolute;
        top: 3px;
        left: 3px;
        width: 20px;
        height: 20px;
        border-radius: 50%;
        background: white;
        transition: transform 0.3s ease;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    .toggle-switch.sm .toggle-knob {
        width: 16px;
        height: 16px;
    }
    .toggle-switch.on .toggle-knob {
        transform: translateX(22px);
    }
    .toggle-switch.sm.on .toggle-knob {
        transform: translateX(18px);
    }

    /* Threshold */
    .threshold-section {
        padding: 1.25rem;
        background: #0a0a12;
        border: 1px solid #1a1a2e;
        border-radius: 10px;
        transition: opacity 0.2s;
    }
    .threshold-section.disabled {
        opacity: 0.4;
        pointer-events: none;
    }
    .threshold-header {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        margin-bottom: 1rem;
    }
    .threshold-value {
        font-size: 1.25rem;
        font-weight: 800;
        color: #3b82f6;
        font-family: "JetBrains Mono", monospace;
        background: #3b82f615;
        padding: 0.25rem 0.75rem;
        border-radius: 8px;
    }
    .slider {
        width: 100%;
        height: 4px;
        -webkit-appearance: none;
        appearance: none;
        background: #222;
        border-radius: 2px;
        outline: none;
    }
    .slider::-webkit-slider-thumb {
        -webkit-appearance: none;
        width: 18px;
        height: 18px;
        border-radius: 50%;
        background: #3b82f6;
        cursor: pointer;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.4);
        border: 2px solid white;
    }
    .slider-labels {
        display: flex;
        justify-content: space-between;
        font-size: 0.5625rem;
        color: #444;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 0.5rem;
    }

    /* Info Sidebar */
    .info-sidebar {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
    }
    .insight-card {
        background: linear-gradient(135deg, #3b82f615, #6366f115);
        border: 1px solid #3b82f622;
        border-radius: 12px;
        padding: 1.25rem;
    }
    .insight-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: #3b82f6;
        font-weight: 700;
        font-size: 0.8125rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.75rem;
    }
    .insight-card p {
        color: #888;
        font-size: 0.8125rem;
        margin: 0;
        line-height: 1.5;
    }
    .insight-card strong {
        color: white;
    }

    .logic-card {
        background: #0f0f17;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        padding: 1.25rem;
    }
    .logic-card h4 {
        display: flex;
        align-items: center;
        gap: 0.375rem;
        font-size: 0.8125rem;
        font-weight: 600;
        color: #ccc;
        margin: 0 0 1rem;
    }
    .logic-item {
        padding-left: 0.875rem;
        margin-bottom: 0.75rem;
        border-left: 2px solid;
    }
    .logic-item.blue {
        border-color: #3b82f644;
    }
    .logic-item.cyan {
        border-color: #06b6d444;
    }
    .logic-item.red {
        border-color: #ef444444;
    }
    .logic-title {
        display: block;
        font-size: 0.6875rem;
        font-weight: 700;
        color: white;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.25rem;
    }
    .logic-desc {
        display: block;
        font-size: 0.625rem;
        color: #555;
        line-height: 1.5;
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

    @keyframes pulse {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.5;
        }
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
    @keyframes spin {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }

    @media (max-width: 1024px) {
        .stats-grid {
            grid-template-columns: repeat(2, 1fr);
        }
        .controls-grid {
            grid-template-columns: 1fr;
        }
        .detail-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }
</style>
