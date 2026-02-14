<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { api } from "$lib/api/client";
  import TimeseriesChart from "$lib/components/charts/TimeseriesChart.svelte";
  import AttackTypesPie from "$lib/components/charts/AttackTypesPie.svelte";
  import type { TrafficTimeSeries } from "$lib/types";
  import {
    Activity,
    RefreshCw,
    Pause,
    Play,
    AlertTriangle,
    ShieldCheck,
    BarChart3,
    Shield,
    Zap,
    TrendingUp,
  } from "lucide-svelte";

  let timelineData: TrafficTimeSeries[] = [];
  let isRefreshing = false;
  let lastUpdate = new Date();
  let lastUpdateText = "just now";
  let autoRefreshEnabled = true;
  let connectionError = false;
  let consecutiveFailures = 0;
  let refreshInterval: any;
  let timeUpdateInterval: any;

  // Stats
  let totalRequests = 0;
  let totalBlocked = 0;
  let blockRate = "0.0";

  let attackTypesData: {
    id: string;
    label: string;
    value: number;
    color: string;
  }[] = [];

  const categoryColors: Record<string, string> = {
    SqlInjection: "#ef4444",
    Xss: "#f59e0b",
    PathTraversal: "#3b82f6",
    CommandInjection: "#8b5cf6",
    RateLimitExceeded: "#6366f1",
    BotDetected: "#ec4899",
    MlAnomaly: "#14b8a6",
    ThreatIntel: "#f97316",
    Other: "#6b7280",
  };

  function getRelativeTime(date: Date) {
    const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);
    if (seconds < 5) return "just now";
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3600)}h ago`;
  }

  async function loadData() {
    if (isRefreshing) return;
    isRefreshing = true;
    try {
      const [history, breakdown, statsRes] = await Promise.all([
        api.getTrafficHistory(),
        api.getAttackBreakdown(),
        api.getStats(),
      ]);

      timelineData = history;

      attackTypesData = breakdown
        .filter((item: any) => item.count > 0)
        .map((item: any) => ({
          id: item.category,
          label: item.display_name,
          value: item.count,
          color: categoryColors[item.category] || "#6b7280",
        }));

      totalRequests = statsRes.total_requests || 0;
      totalBlocked = statsRes.blocked_requests || 0;
      blockRate =
        totalRequests > 0
          ? ((totalBlocked / totalRequests) * 100).toFixed(1)
          : "0.0";

      lastUpdate = new Date();
      connectionError = false;
      consecutiveFailures = 0;
    } catch (e) {
      console.error("Failed to load analytics", e);
      consecutiveFailures++;
      if (consecutiveFailures >= 3) connectionError = true;
    } finally {
      isRefreshing = false;
      lastUpdateText = getRelativeTime(lastUpdate);
    }
  }

  function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    if (autoRefreshEnabled) {
      loadData();
      refreshInterval = setInterval(loadData, 5000);
    } else {
      clearInterval(refreshInterval);
    }
  }

  onMount(() => {
    loadData();
    refreshInterval = setInterval(loadData, 5000);
    timeUpdateInterval = setInterval(() => {
      lastUpdateText = getRelativeTime(lastUpdate);
    }, 1000);
  });

  onDestroy(() => {
    if (refreshInterval) clearInterval(refreshInterval);
    if (timeUpdateInterval) clearInterval(timeUpdateInterval);
  });
</script>

<div class="page">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="title-row">
        <div class="icon-circle">
          <BarChart3 size={24} />
        </div>
        <div>
          <h1>Real-Time Analytics</h1>
          <p class="subtitle">
            {#if connectionError}
              <span class="error-text">
                <AlertTriangle size={12} /> Backend unreachable
              </span>
            {:else}
              Last updated: {lastUpdateText}
            {/if}
          </p>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <button
        class="btn-icon"
        on:click={loadData}
        disabled={isRefreshing}
        title="Refresh now"
      >
        <RefreshCw size={16} class={isRefreshing ? "spin" : ""} />
      </button>
      <button class="btn-toggle" on:click={toggleAutoRefresh}>
        {#if autoRefreshEnabled}
          <Pause size={14} /> Pause
        {:else}
          <Play size={14} /> Resume
        {/if}
      </button>
    </div>
  </div>

  <!-- Quick Stats -->
  <div class="quick-stats">
    <div class="qs-card">
      <Activity size={16} class="qs-icon" />
      <div class="qs-content">
        <span class="qs-label">Total Requests</span>
        <span class="qs-value">{totalRequests.toLocaleString()}</span>
      </div>
    </div>
    <div class="qs-card">
      <Shield size={16} class="qs-icon red" />
      <div class="qs-content">
        <span class="qs-label">Blocked</span>
        <span class="qs-value red">{totalBlocked.toLocaleString()}</span>
      </div>
    </div>
    <div class="qs-card">
      <TrendingUp size={16} class="qs-icon amber" />
      <div class="qs-content">
        <span class="qs-label">Block Rate</span>
        <span class="qs-value amber">{blockRate}%</span>
      </div>
    </div>
    <div class="qs-card">
      <Zap size={16} class="qs-icon cyan" />
      <div class="qs-content">
        <span class="qs-label">Attack Types</span>
        <span class="qs-value cyan">{attackTypesData.length}</span>
      </div>
    </div>
  </div>

  <!-- Charts Grid -->
  <div class="charts-grid">
    <div class="chart-panel">
      <h3><Activity size={16} /> Traffic Volume (Real-Time)</h3>
      <div class="chart-container">
        {#if timelineData.length > 0}
          <TimeseriesChart data={timelineData} height={400} />
        {:else}
          <div class="empty-chart">
            <Activity size={32} class="empty-icon" />
            <p>Waiting for traffic data...</p>
            <p class="empty-hint">
              Data appears as requests flow through the WAF
            </p>
          </div>
        {/if}
      </div>
    </div>

    <div class="chart-panel">
      <h3><Shield size={16} /> Attack Type Distribution</h3>
      <div class="chart-container">
        {#if attackTypesData.length > 0}
          <AttackTypesPie data={attackTypesData} />
        {:else}
          <div class="empty-chart">
            <ShieldCheck size={32} class="empty-icon" />
            <p>No attacks detected yet</p>
            <p class="empty-hint">Data from real WAF blocks</p>
          </div>
        {/if}
      </div>
    </div>
  </div>
</div>

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
    background: linear-gradient(135deg, #3b82f6, #06b6d4);
    color: white;
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
  .error-text {
    color: #ef4444;
    display: flex;
    align-items: center;
    gap: 0.25rem;
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
  .btn-icon:disabled {
    opacity: 0.5;
  }
  .btn-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: 1px solid #333;
    background: #111;
    color: #ccc;
    font-weight: 500;
    font-size: 0.8125rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-toggle:hover {
    border-color: #555;
    color: white;
  }

  /* Quick Stats */
  .quick-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
  }
  .qs-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    padding: 1rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }
  :global(.qs-icon) {
    color: #3b82f6;
    flex-shrink: 0;
  }
  :global(.qs-icon.red) {
    color: #ef4444;
  }
  :global(.qs-icon.amber) {
    color: #f59e0b;
  }
  :global(.qs-icon.cyan) {
    color: #06b6d4;
  }
  .qs-content {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }
  .qs-label {
    font-size: 0.625rem;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .qs-value {
    font-size: 1.25rem;
    font-weight: 800;
    color: white;
    font-family: "JetBrains Mono", monospace;
  }
  .qs-value.red {
    color: #ef4444;
  }
  .qs-value.amber {
    color: #f59e0b;
  }
  .qs-value.cyan {
    color: #06b6d4;
  }

  /* Charts Grid */
  .charts-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .chart-panel {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    overflow: hidden;
  }
  .chart-panel h3 {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
    font-weight: 600;
    color: #ccc;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid #1a1a2e;
    margin: 0;
  }
  .chart-container {
    padding: 1rem;
    min-height: 400px;
  }
  .empty-chart {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 400px;
    color: #555;
  }
  :global(.empty-icon) {
    color: #333;
    margin-bottom: 0.75rem;
  }
  .empty-chart p {
    margin: 0;
    font-size: 0.875rem;
  }
  .empty-hint {
    font-size: 0.75rem;
    color: #444;
    margin-top: 0.25rem !important;
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

  @media (max-width: 1024px) {
    .charts-grid {
      grid-template-columns: 1fr;
    }
    .quick-stats {
      grid-template-columns: repeat(2, 1fr);
    }
  }
</style>
