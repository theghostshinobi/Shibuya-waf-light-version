<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import * as echarts from "echarts";
  import { api } from "$lib/api/client";
  import type {
    DashboardStats,
    HealthStatus,
    TrafficTimeSeries,
  } from "$lib/types";
  import KernelShield from "$lib/components/KernelShield.svelte";
  import {
    Shield,
    ShieldAlert,
    ShieldCheck,
    Activity,
    Cpu,
    Zap,
    Globe,
    LayoutDashboard,
    Sliders,
    AlertTriangle,
    Clock,
    BarChart3,
    Server,
    Eye,
    Lock,
    Wifi,
    Database,
    Bug,
    RefreshCw,
    X,
    CheckCircle,
    TrendingUp,
    Ban,
    Timer,
    Brain,
  } from "lucide-svelte";

  // -- State --
  let isAdvancedMode = false;
  let trafficChartDiv: HTMLDivElement;
  let trafficChart: echarts.ECharts;
  let chartResizeObserver: ResizeObserver;
  let kernelActive = true;
  let kernelDropped = 0;

  let stats: DashboardStats = {
    total_requests: 0,
    blocked_requests: 0,
    allowed_requests: 0,
    avg_latency_ms: 0,
    rules_triggered: 0,
    ml_detections: 0,
    threat_intel_blocks: 0,
    ebpf_drops: 0,
  };

  let health: HealthStatus = {
    status: "Loading...",
    uptime_human: "0s",
    components: { proxy: "", rule_engine: "", ebpf: "", wasm_plugins: "" },
  };

  let interval: any;
  let panicActive = false;
  let panicLoading = false;

  // -- Detail Panel --
  let activeDetail: string | null = null;

  // -- Toast --
  let showToast = false;
  let toastMessage = "";
  let toastType: "success" | "error" | "info" = "success";

  // -- Lifecycle --
  async function refreshData() {
    try {
      const [s, h] = await Promise.all([api.getStats(), api.getHealth()]);
      stats = s;
      health = h;
      kernelActive = h.components.ebpf?.includes("ACTIVE") || false;
      kernelDropped = s.blocked_requests;

      if (isAdvancedMode && trafficChart) {
        await refreshChart();
      }
    } catch (e) {
      console.error("API Error", e);
    }
  }

  async function refreshChart() {
    try {
      const history = await api.getTrafficHistory();
      updateChart(history);
    } catch (e) {
      console.error("Failed to load traffic history", e);
    }
  }

  onMount(() => {
    refreshData();
    interval = setInterval(refreshData, 2000);
    if (isAdvancedMode) initChart();
  });

  onDestroy(() => {
    if (interval) clearInterval(interval);
    if (trafficChart) trafficChart.dispose();
    if (chartResizeObserver) chartResizeObserver.disconnect();
  });

  $: if (isAdvancedMode && trafficChartDiv) {
    setTimeout(() => initChart(), 50);
  }

  async function handleShieldToggle() {
    try {
      const res = await api.toggleModule("ebpf");
      kernelActive = res.enabled;
      refreshData();
    } catch (e) {
      console.error(e);
    }
  }

  async function triggerPanic() {
    if (
      !confirm(
        "⚠️ ACTIVATE PANIC MODE?\nThis will set Paranoia Level 4 and block ALL suspicious traffic. Continue?",
      )
    )
      return;
    panicLoading = true;
    try {
      await api.panic();
      panicActive = true;
      refreshData();
      notify("PANIC MODE ACTIVATED — Paranoia Level 4, full blocking", "error");
    } catch (e: any) {
      notify("Panic Failed: " + e.message, "error");
    } finally {
      panicLoading = false;
    }
  }

  function notify(msg: string, type: "success" | "error" | "info") {
    toastMessage = msg;
    toastType = type;
    showToast = true;
    setTimeout(() => {
      showToast = false;
    }, 3000);
  }

  function toggleDetail(id: string) {
    activeDetail = activeDetail === id ? null : id;
  }

  $: protectionRate =
    stats.total_requests > 0
      ? ((stats.blocked_requests / stats.total_requests) * 100).toFixed(1)
      : "0.0";

  $: allowRate =
    stats.total_requests > 0
      ? ((stats.allowed_requests / stats.total_requests) * 100).toFixed(1)
      : "100.0";

  // -- Charting --
  function initChart() {
    if (trafficChart) trafficChart.dispose();
    if (!trafficChartDiv) return;

    trafficChart = echarts.init(trafficChartDiv);

    const option = {
      backgroundColor: "transparent",
      tooltip: {
        trigger: "axis",
        backgroundColor: "rgba(10, 10, 15, 0.95)",
        borderColor: "#1a1a2e",
        textStyle: { color: "#e2e8f0", fontSize: 12 },
      },
      grid: {
        top: "15%",
        left: "3%",
        right: "4%",
        bottom: "3%",
        containLabel: true,
      },
      xAxis: {
        type: "category",
        boundaryGap: false,
        data: [],
        axisLine: { lineStyle: { color: "#1a1a2e" } },
        axisLabel: { color: "#555" },
      },
      yAxis: {
        type: "value",
        splitLine: { lineStyle: { color: "#111118" } },
        axisLabel: { color: "#555" },
      },
      series: [
        {
          name: "RPS",
          type: "line",
          smooth: true,
          data: [],
          lineStyle: { width: 2, color: "#0ea5e9" },
          showSymbol: false,
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "rgba(14,165,233,0.25)" },
              { offset: 1, color: "rgba(14,165,233,0.02)" },
            ]),
          },
        },
        {
          name: "Blocked",
          type: "line",
          smooth: true,
          data: [],
          lineStyle: { width: 2, color: "#ef4444" },
          showSymbol: false,
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "rgba(239,68,68,0.15)" },
              { offset: 1, color: "rgba(239,68,68,0.02)" },
            ]),
          },
        },
      ],
      legend: {
        data: ["RPS", "Blocked"],
        textStyle: { color: "#666" },
        top: 5,
        right: 10,
      },
    };

    trafficChart.setOption(option);

    chartResizeObserver = new ResizeObserver(() => {
      trafficChart?.resize();
    });
    chartResizeObserver.observe(trafficChartDiv);
  }

  function updateChart(history: TrafficTimeSeries[]) {
    if (!trafficChart || !history.length) return;
    trafficChart.setOption({
      xAxis: {
        data: history.map((t: any) => {
          const d = new Date(t.timestamp);
          return d.toLocaleTimeString();
        }),
      },
      series: [
        { data: history.map((t: any) => t.total_requests || 0) },
        { data: history.map((t: any) => t.blocked_requests || 0) },
      ],
    });
  }

  function getComponentStatus(status: string): string {
    if (!status) return "unknown";
    const s = status.toLowerCase();
    if (s.includes("active") || s.includes("running") || s.includes("healthy"))
      return "active";
    if (s.includes("loaded") || s.includes("ready")) return "loaded";
    if (s.includes("offline") || s.includes("disabled")) return "offline";
    return "unknown";
  }
</script>

<div class="page">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="title-row">
        <div class="icon-circle">
          <LayoutDashboard size={24} />
        </div>
        <div>
          <h1>Dashboard</h1>
          <p class="subtitle">
            <span
              class="status-indicator"
              class:online={health.status !== "Loading..."}
            >
              <span class="dot"></span>
            </span>
            {health.status} · Uptime {health.uptime_human}
          </p>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <div class="mode-switch">
        <button
          class="mode-btn"
          class:active={!isAdvancedMode}
          on:click={() => (isAdvancedMode = false)}
        >
          <LayoutDashboard size={13} /> Simple
        </button>
        <button
          class="mode-btn"
          class:active={isAdvancedMode}
          on:click={() => (isAdvancedMode = true)}
        >
          <Sliders size={13} /> Advanced
        </button>
      </div>
    </div>
  </div>

  {#if !isAdvancedMode}
    <!-- ==================== SIMPLE MODE ==================== -->
    <div class="simple-layout">
      <!-- Primary stats row -->
      <div class="primary-stats">
        <button
          class="primary-card"
          class:expanded={activeDetail === "total"}
          on:click={() => toggleDetail("total")}
        >
          <div class="primary-icon blue"><Activity size={20} /></div>
          <div class="primary-info">
            <span class="primary-label">Total Requests</span>
            <span class="primary-value"
              >{stats.total_requests.toLocaleString()}</span
            >
          </div>
        </button>
        <button
          class="primary-card"
          class:expanded={activeDetail === "blocked"}
          on:click={() => toggleDetail("blocked")}
        >
          <div class="primary-icon red"><Shield size={20} /></div>
          <div class="primary-info">
            <span class="primary-label">Blocked</span>
            <span class="primary-value red"
              >{stats.blocked_requests.toLocaleString()}</span
            >
          </div>
        </button>
        <button
          class="primary-card"
          class:expanded={activeDetail === "allowed"}
          on:click={() => toggleDetail("allowed")}
        >
          <div class="primary-icon green"><ShieldCheck size={20} /></div>
          <div class="primary-info">
            <span class="primary-label">Allowed</span>
            <span class="primary-value green"
              >{stats.allowed_requests.toLocaleString()}</span
            >
          </div>
        </button>
      </div>

      <!-- Detail Panel for Simple Mode -->
      {#if activeDetail}
        <div class="detail-panel simple-mode-detail">
          <div class="detail-header">
            <h3>
              {#if activeDetail === "total"}<Activity size={16} /> Request Overview
              {:else if activeDetail === "blocked"}<Ban size={16} /> Block Analysis
              {:else if activeDetail === "allowed"}<ShieldCheck size={16} /> Allow
                Analysis
              {/if}
            </h3>
            <button class="btn-close" on:click={() => (activeDetail = null)}
              ><X size={14} /></button
            >
          </div>
          <div class="detail-body">
            <div class="detail-grid">
              {#if activeDetail === "total"}
                <div class="d-item">
                  <span class="d-label">Total Requests</span><span class="d-val"
                    >{stats.total_requests.toLocaleString()}</span
                  >
                </div>
                <div class="d-item">
                  <span class="d-label">Avg Latency</span><span class="d-val"
                    >{stats.avg_latency_ms.toFixed(2)}ms</span
                  >
                </div>
              {:else if activeDetail === "blocked"}
                <div class="d-item">
                  <span class="d-label">Total Blocked</span><span
                    class="d-val red"
                    >{stats.blocked_requests.toLocaleString()}</span
                  >
                </div>
                <div class="d-item">
                  <span class="d-label">By Rules</span><span class="d-val"
                    >{stats.rules_triggered}</span
                  >
                </div>
                <div class="d-item">
                  <span class="d-label">By ML</span><span class="d-val"
                    >{stats.ml_detections}</span
                  >
                </div>
              {:else if activeDetail === "allowed"}
                <div class="d-item">
                  <span class="d-label">Total Allowed</span><span
                    class="d-val green"
                    >{stats.allowed_requests.toLocaleString()}</span
                  >
                </div>
                <div class="d-item">
                  <span class="d-label">Allow Rate</span><span class="d-val"
                    >{allowRate}%</span
                  >
                </div>
              {/if}
            </div>
          </div>
        </div>
      {/if}

      <!-- Big visual: Protection Score + Kernel Shield -->
      <div class="simple-body">
        <div class="protection-card">
          <div class="protection-header">
            <Shield size={18} />
            <span>Protection Status</span>
          </div>
          <div class="protection-main">
            <div class="score-ring">
              <svg viewBox="0 0 120 120" class="score-svg">
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke="#1a1a2e"
                  stroke-width="8"
                />
                <circle
                  cx="60"
                  cy="60"
                  r="54"
                  fill="none"
                  stroke={parseFloat(protectionRate) > 50
                    ? "#10b981"
                    : parseFloat(protectionRate) > 0
                      ? "#f59e0b"
                      : "#3b82f6"}
                  stroke-width="8"
                  stroke-dasharray={`${(parseFloat(protectionRate) / 100) * 339.3} 339.3`}
                  stroke-linecap="round"
                  transform="rotate(-90 60 60)"
                />
              </svg>
              <div class="score-text">
                <span class="score-number">{protectionRate}</span>
                <span class="score-unit">%</span>
              </div>
            </div>
            <div class="protection-details">
              <div class="detail-row">
                <span class="detail-label"><Shield size={12} /> Block Rate</span
                >
                <span class="detail-value">{protectionRate}%</span>
              </div>
              <div class="progress-bar">
                <div
                  class="progress-fill red"
                  style="width: {protectionRate}%"
                ></div>
              </div>
              <div class="detail-row">
                <span class="detail-label"
                  ><CheckCircle size={12} /> Allow Rate</span
                >
                <span class="detail-value">{allowRate}%</span>
              </div>
              <div class="progress-bar">
                <div
                  class="progress-fill green"
                  style="width: {allowRate}%"
                ></div>
              </div>
              <div class="detail-row mt">
                <span class="detail-label"><Timer size={12} /> Avg Latency</span
                >
                <span class="detail-value mono"
                  >{stats.avg_latency_ms.toFixed(2)}ms</span
                >
              </div>
              <div class="detail-row">
                <span class="detail-label"
                  ><Zap size={12} /> Rules Triggered</span
                >
                <span class="detail-value mono">{stats.rules_triggered}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="shield-card">
          <KernelShield
            active={kernelActive}
            droppedCount={kernelDropped}
            on:toggle={handleShieldToggle}
          />
        </div>
      </div>

      <!-- System Status -->
      <div class="system-status-card">
        <div class="system-header">
          <Server size={14} />
          <span>System Components</span>
        </div>
        <div class="components-row">
          {#each Object.entries(health.components) as [name, status]}
            <div
              class="component-chip"
              class:active={getComponentStatus(status) === "active" ||
                getComponentStatus(status) === "loaded"}
            >
              <span class="comp-dot"></span>
              <span class="comp-name">{name.replace("_", " ")}</span>
              <span class="comp-status">{status || "N/A"}</span>
            </div>
          {/each}
        </div>
      </div>
    </div>
  {:else}
    <!-- ==================== ADVANCED MODE ==================== -->
    <!-- Stats Grid — Clickable -->
    <div class="stats-grid">
      <button
        class="stat-card"
        class:expanded={activeDetail === "total"}
        on:click={() => toggleDetail("total")}
      >
        <div class="stat-icon-bg blue"><Activity size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Total Requests</span>
          <span class="stat-val">{stats.total_requests.toLocaleString()}</span>
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "blocked"}
        on:click={() => toggleDetail("blocked")}
      >
        <div class="stat-icon-bg red"><Ban size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Blocked</span>
          <span class="stat-val red"
            >{stats.blocked_requests.toLocaleString()}</span
          >
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "allowed"}
        on:click={() => toggleDetail("allowed")}
      >
        <div class="stat-icon-bg green"><ShieldCheck size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Allowed</span>
          <span class="stat-val green"
            >{stats.allowed_requests.toLocaleString()}</span
          >
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "latency"}
        on:click={() => toggleDetail("latency")}
      >
        <div class="stat-icon-bg amber"><Timer size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Avg Latency</span>
          <span class="stat-val amber">{stats.avg_latency_ms.toFixed(2)}ms</span
          >
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "rules"}
        on:click={() => toggleDetail("rules")}
      >
        <div class="stat-icon-bg violet"><Zap size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Rules Triggered</span>
          <span class="stat-val violet">{stats.rules_triggered}</span>
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "ml"}
        on:click={() => toggleDetail("ml")}
      >
        <div class="stat-icon-bg cyan"><Brain size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">ML Detections</span>
          <span class="stat-val cyan">{stats.ml_detections}</span>
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "threat"}
        on:click={() => toggleDetail("threat")}
      >
        <div class="stat-icon-bg pink"><Globe size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">Threat Intel</span>
          <span class="stat-val pink">{stats.threat_intel_blocks}</span>
        </div>
      </button>

      <button
        class="stat-card"
        class:expanded={activeDetail === "ebpf"}
        on:click={() => toggleDetail("ebpf")}
      >
        <div class="stat-icon-bg orange"><Database size={18} /></div>
        <div class="stat-meta">
          <span class="stat-label">eBPF Drops</span>
          <span class="stat-val orange">{stats.ebpf_drops}</span>
        </div>
      </button>
    </div>

    <!-- Detail Panel -->
    {#if activeDetail}
      <div class="detail-panel">
        <div class="detail-header">
          <h3>
            {#if activeDetail === "total"}<Activity size={16} /> Request Overview
            {:else if activeDetail === "blocked"}<Ban size={16} /> Block Analysis
            {:else if activeDetail === "allowed"}<ShieldCheck size={16} /> Allow
              Analysis
            {:else if activeDetail === "latency"}<Timer size={16} /> Latency Details
            {:else if activeDetail === "rules"}<Zap size={16} /> Rule Engine Details
            {:else if activeDetail === "ml"}<Brain size={16} /> ML Engine Details
            {:else if activeDetail === "threat"}<Globe size={16} /> Threat Intelligence
            {:else}<Database size={16} /> eBPF Kernel Details
            {/if}
          </h3>
          <button class="btn-close" on:click={() => (activeDetail = null)}
            ><X size={14} /></button
          >
        </div>
        <div class="detail-body">
          <div class="detail-grid">
            {#if activeDetail === "total"}
              <div class="d-item">
                <span class="d-label">Total Requests</span><span class="d-val"
                  >{stats.total_requests.toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Blocked</span><span class="d-val red"
                  >{stats.blocked_requests.toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Allowed</span><span class="d-val green"
                  >{stats.allowed_requests.toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Block Rate</span><span class="d-val"
                  >{protectionRate}%</span
                >
              </div>
            {:else if activeDetail === "blocked"}
              <div class="d-item">
                <span class="d-label">Total Blocked</span><span
                  class="d-val red"
                  >{stats.blocked_requests.toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">By Rules</span><span class="d-val"
                  >{stats.rules_triggered}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">By ML</span><span class="d-val"
                  >{stats.ml_detections}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">By Threat Intel</span><span class="d-val"
                  >{stats.threat_intel_blocks}</span
                >
              </div>
            {:else if activeDetail === "allowed"}
              <div class="d-item">
                <span class="d-label">Total Allowed</span><span
                  class="d-val green"
                  >{stats.allowed_requests.toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Allow Rate</span><span class="d-val"
                  >{allowRate}%</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Clean Traffic</span><span class="d-val"
                  >{(
                    stats.total_requests - stats.blocked_requests
                  ).toLocaleString()}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Status</span><span class="d-val"
                  >{health.status}</span
                >
              </div>
            {:else if activeDetail === "latency"}
              <div class="d-item">
                <span class="d-label">Avg Latency</span><span class="d-val"
                  >{stats.avg_latency_ms.toFixed(2)}ms</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Proxy Status</span><span class="d-val"
                  >{health.components.proxy || "N/A"}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">System Status</span><span class="d-val"
                  >{health.status}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Uptime</span><span class="d-val"
                  >{health.uptime_human}</span
                >
              </div>
            {:else if activeDetail === "rules"}
              <div class="d-item">
                <span class="d-label">Rules Triggered</span><span
                  class="d-val violet">{stats.rules_triggered}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Engine Status</span><span class="d-val"
                  >{health.components.rule_engine || "N/A"}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Total Blocked</span><span class="d-val"
                  >{stats.blocked_requests}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">% of Blocks</span><span class="d-val"
                  >{stats.blocked_requests > 0
                    ? (
                        (stats.rules_triggered / stats.blocked_requests) *
                        100
                      ).toFixed(1)
                    : "0.0"}%</span
                >
              </div>
            {:else if activeDetail === "ml"}
              <div class="d-item">
                <span class="d-label">ML Detections</span><span
                  class="d-val cyan">{stats.ml_detections}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">% of Blocks</span><span class="d-val"
                  >{stats.blocked_requests > 0
                    ? (
                        (stats.ml_detections / stats.blocked_requests) *
                        100
                      ).toFixed(1)
                    : "0.0"}%</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Model Status</span><span class="d-val"
                  >Active</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Total Requests</span><span class="d-val"
                  >{stats.total_requests.toLocaleString()}</span
                >
              </div>
            {:else if activeDetail === "threat"}
              <div class="d-item">
                <span class="d-label">Threat Intel Blocks</span><span
                  class="d-val pink">{stats.threat_intel_blocks}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">% of Blocks</span><span class="d-val"
                  >{stats.blocked_requests > 0
                    ? (
                        (stats.threat_intel_blocks / stats.blocked_requests) *
                        100
                      ).toFixed(1)
                    : "0.0"}%</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Feed Status</span><span class="d-val"
                  >Active</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Uptime</span><span class="d-val"
                  >{health.uptime_human}</span
                >
              </div>
            {:else}
              <div class="d-item">
                <span class="d-label">eBPF Drops</span><span
                  class="d-val orange">{stats.ebpf_drops}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Kernel Status</span><span class="d-val"
                  >{health.components.ebpf || "N/A"}</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">% of Blocks</span><span class="d-val"
                  >{stats.blocked_requests > 0
                    ? (
                        (stats.ebpf_drops / stats.blocked_requests) *
                        100
                      ).toFixed(1)
                    : "0.0"}%</span
                >
              </div>
              <div class="d-item">
                <span class="d-label">Mode</span><span class="d-val"
                  >{kernelActive ? "Active" : "Inactive"}</span
                >
              </div>
            {/if}
          </div>
        </div>
      </div>
    {/if}

    <!-- Two column layout -->
    <div class="adv-grid">
      <!-- Live Chart -->
      <div class="chart-panel">
        <div class="panel-header">
          <Activity size={16} />
          <span>Live Traffic Analysis</span>
          <div class="panel-badges">
            <span class="badge-live">LIVE</span>
          </div>
        </div>
        <div class="chart-container" bind:this={trafficChartDiv}></div>
      </div>

      <!-- Right sidebar -->
      <div class="adv-sidebar">
        <!-- Block Rate -->
        <div class="rate-card">
          <span class="rate-label">Block Rate</span>
          <span class="rate-value red">{protectionRate}%</span>
          <div class="progress-bar">
            <div
              class="progress-fill red"
              style="width: {protectionRate}%"
            ></div>
          </div>
        </div>

        <!-- Allow Rate -->
        <div class="rate-card">
          <span class="rate-label">Allow Rate</span>
          <span class="rate-value green">{allowRate}%</span>
          <div class="progress-bar">
            <div class="progress-fill green" style="width: {allowRate}%"></div>
          </div>
        </div>

        <!-- Components -->
        <div class="components-card">
          <span class="comp-title">System Components</span>
          {#each Object.entries(health.components) as [name, status]}
            <div class="comp-row">
              <span class="comp-icon">
                {#if name === "proxy"}<Server size={13} />
                {:else if name === "rule_engine"}<Shield size={13} />
                {:else if name === "ebpf"}<Cpu size={13} />
                {:else}<Database size={13} />
                {/if}
              </span>
              <span class="comp-name">{name.replace("_", " ")}</span>
              <span
                class="comp-badge"
                class:active={getComponentStatus(status) === "active" ||
                  getComponentStatus(status) === "loaded"}
                class:offline={getComponentStatus(status) === "offline"}
              >
                {#if getComponentStatus(status) === "active" || getComponentStatus(status) === "loaded"}
                  <CheckCircle size={10} />
                {/if}
                {status || "N/A"}
              </span>
            </div>
          {/each}
        </div>

        <!-- Panic -->
        <button
          class="panic-btn"
          class:active={panicActive}
          on:click={triggerPanic}
          disabled={panicLoading}
        >
          <AlertTriangle size={16} />
          {#if panicLoading}
            ACTIVATING...
          {:else if panicActive}
            PANIC ACTIVE
          {:else}
            PANIC MODE
          {/if}
        </button>
      </div>
    </div>
  {/if}
</div>

<!-- Toast -->
{#if showToast}
  <div class="toast {toastType}">
    {#if toastType === "success"}<ShieldCheck size={16} />
    {:else if toastType === "error"}<AlertTriangle size={16} />
    {:else}<Activity size={16} />
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
    background: linear-gradient(135deg, #0ea5e9, #6366f1);
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
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .status-indicator {
    display: flex;
    align-items: center;
  }
  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: #10b981;
    animation: pulse 2s ease infinite;
  }
  .status-indicator:not(.online) .dot {
    background: #f59e0b;
    animation: none;
  }

  /* Mode Switch */
  .mode-switch {
    display: flex;
    background: #0a0a12;
    border: 1px solid #1a1a2e;
    border-radius: 10px;
    overflow: hidden;
  }
  .mode-btn {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    padding: 0.5rem 1rem;
    border: none;
    background: transparent;
    color: #666;
    font-weight: 500;
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .mode-btn.active {
    background: #1a1a2e;
    color: white;
  }
  .mode-btn:hover:not(.active) {
    color: #999;
  }

  /* ==================== SIMPLE MODE ==================== */
  .simple-layout {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .primary-stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
  }
  .primary-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 14px;
    padding: 1.25rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    /* Interactive */
    cursor: pointer;
    transition: all 0.2s ease;
    text-align: left;
    color: inherit;
    appearance: none;
    -webkit-appearance: none;
    font-family: inherit;
  }
  .primary-card:hover {
    border-color: #3b82f6;
    background: #151520;
    transform: translateY(-2px);
  }
  .primary-card.expanded {
    border-color: #3b82f6;
    background: #151520;
    box-shadow: 0 0 0 1px #3b82f633;
  }

  .simple-mode-detail {
    grid-column: 1 / -1;
    margin-top: 1rem;
    animation: slideDown 0.3s ease-out;
  }
  .primary-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .primary-icon.blue {
    background: #3b82f615;
    color: #3b82f6;
  }
  .primary-icon.red {
    background: #ef444415;
    color: #ef4444;
  }
  .primary-icon.green {
    background: #10b98115;
    color: #10b981;
  }
  .primary-info {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }
  .primary-label {
    font-size: 0.6875rem;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .primary-value {
    font-size: 1.75rem;
    font-weight: 800;
    color: white;
    font-family: "JetBrains Mono", monospace;
    line-height: 1.1;
  }
  .primary-value.red {
    color: #ef4444;
  }
  .primary-value.green {
    color: #10b981;
  }

  .simple-body {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  /* Protection Card */
  .protection-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 14px;
    overflow: hidden;
  }
  .protection-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid #1a1a2e;
    color: #ccc;
    font-weight: 600;
    font-size: 0.8125rem;
  }
  .protection-main {
    display: flex;
    align-items: center;
    padding: 1.5rem;
    gap: 2rem;
  }
  .score-ring {
    position: relative;
    width: 120px;
    height: 120px;
    flex-shrink: 0;
  }
  .score-svg {
    width: 100%;
    height: 100%;
  }
  .score-text {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    display: flex;
    align-items: baseline;
    gap: 2px;
  }
  .score-number {
    font-size: 1.75rem;
    font-weight: 800;
    font-family: "JetBrains Mono", monospace;
    color: white;
  }
  .score-unit {
    font-size: 0.875rem;
    color: #888;
    font-weight: 600;
  }
  .protection-details {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .detail-row.mt {
    margin-top: 0.5rem;
  }
  .detail-label {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.6875rem;
    color: #666;
  }
  .detail-value {
    font-size: 0.8125rem;
    font-weight: 600;
    color: #ccc;
  }
  .detail-value.mono {
    font-family: "JetBrains Mono", monospace;
  }
  .progress-bar {
    height: 4px;
    background: #1a1a2e;
    border-radius: 2px;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.5s ease;
  }
  .progress-fill.red {
    background: #ef4444;
  }
  .progress-fill.green {
    background: #10b981;
  }

  /* Shield Card */
  .shield-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 14px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* System Status */
  .system-status-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 14px;
    overflow: hidden;
  }
  .system-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.875rem 1.25rem;
    border-bottom: 1px solid #1a1a2e;
    color: #888;
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .components-row {
    display: flex;
    gap: 0.75rem;
    padding: 1rem 1.25rem;
    flex-wrap: wrap;
  }
  .component-chip {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background: #0a0a12;
    border: 1px solid #1a1a2e;
    border-radius: 8px;
    font-size: 0.6875rem;
    flex: 1;
    min-width: 140px;
  }
  .component-chip .comp-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #ef4444;
    flex-shrink: 0;
  }
  .component-chip.active .comp-dot {
    background: #10b981;
  }
  .component-chip .comp-name {
    text-transform: capitalize;
    color: #ccc;
    font-weight: 500;
  }
  .component-chip .comp-status {
    margin-left: auto;
    color: #666;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.625rem;
    text-transform: uppercase;
  }

  /* ==================== ADVANCED MODE ==================== */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
  }
  .stat-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    padding: 1rem;
    display: flex;
    align-items: center;
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
    border-color: #3b82f650;
    background: #0f0f1a;
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
  .stat-icon-bg.red {
    background: #ef444415;
    color: #ef4444;
  }
  .stat-icon-bg.green {
    background: #10b98115;
    color: #10b981;
  }
  .stat-icon-bg.amber {
    background: #f59e0b15;
    color: #f59e0b;
  }
  .stat-icon-bg.violet {
    background: #8b5cf615;
    color: #8b5cf6;
  }
  .stat-icon-bg.cyan {
    background: #06b6d415;
    color: #06b6d4;
  }
  .stat-icon-bg.pink {
    background: #ec489915;
    color: #ec4899;
  }
  .stat-icon-bg.orange {
    background: #f9731615;
    color: #f97316;
  }
  .stat-meta {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
    min-width: 0;
  }
  .stat-label {
    font-size: 0.5625rem;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }
  .stat-val {
    font-size: 1.125rem;
    font-weight: 800;
    color: white;
    font-family: "JetBrains Mono", monospace;
  }
  .stat-val.red {
    color: #ef4444;
  }
  .stat-val.green {
    color: #10b981;
  }
  .stat-val.amber {
    color: #f59e0b;
  }
  .stat-val.violet {
    color: #8b5cf6;
  }
  .stat-val.cyan {
    color: #06b6d4;
  }
  .stat-val.pink {
    color: #ec4899;
  }
  .stat-val.orange {
    color: #f97316;
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
  .d-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .d-label {
    font-size: 0.6875rem;
    color: #555;
    font-weight: 500;
  }
  .d-val {
    font-size: 1.125rem;
    font-weight: 700;
    color: white;
    font-family: "JetBrains Mono", monospace;
  }
  .d-val.red {
    color: #ef4444;
  }
  .d-val.green {
    color: #10b981;
  }
  .d-val.violet {
    color: #8b5cf6;
  }
  .d-val.cyan {
    color: #06b6d4;
  }
  .d-val.pink {
    color: #ec4899;
  }
  .d-val.orange {
    color: #f97316;
  }

  /* Advanced Grid */
  .adv-grid {
    display: grid;
    grid-template-columns: 1fr 300px;
    gap: 1rem;
  }
  .chart-panel {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    overflow: hidden;
  }
  .panel-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid #1a1a2e;
    color: #ccc;
    font-weight: 600;
    font-size: 0.8125rem;
  }
  .panel-badges {
    margin-left: auto;
    display: flex;
    gap: 0.5rem;
  }
  .badge-live {
    background: #10b98122;
    color: #10b981;
    font-size: 0.625rem;
    font-weight: 700;
    padding: 0.2rem 0.5rem;
    border-radius: 4px;
    letter-spacing: 0.05em;
  }
  .chart-container {
    height: 300px;
    padding: 0.5rem;
  }

  /* Sidebar */
  .adv-sidebar {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .rate-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    padding: 1rem 1.25rem;
  }
  .rate-label {
    font-size: 0.6875rem;
    color: #555;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.05em;
    display: block;
    margin-bottom: 0.25rem;
  }
  .rate-value {
    font-size: 1.5rem;
    font-weight: 800;
    color: white;
    font-family: "JetBrains Mono", monospace;
    display: block;
    margin-bottom: 0.5rem;
  }
  .rate-value.red {
    color: #ef4444;
  }
  .rate-value.green {
    color: #10b981;
  }

  .components-card {
    background: #0f0f17;
    border: 1px solid #1a1a2e;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .comp-title {
    font-size: 0.6875rem;
    color: #555;
    text-transform: uppercase;
    font-weight: 600;
    letter-spacing: 0.05em;
    margin-bottom: 0.25rem;
  }
  .comp-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .comp-icon {
    color: #555;
    display: flex;
  }
  .comp-row .comp-name {
    flex: 1;
    font-size: 0.8125rem;
    color: #ccc;
    text-transform: capitalize;
    font-weight: 500;
  }
  .comp-badge {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.625rem;
    font-weight: 700;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
  .comp-badge.active {
    color: #10b981;
  }
  .comp-badge.offline {
    color: #ef4444;
  }

  .panic-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.875rem;
    border-radius: 12px;
    border: 1px solid #ef444433;
    background: linear-gradient(135deg, #ef444415, #dc262615);
    color: #ef4444;
    font-weight: 700;
    font-size: 0.8125rem;
    cursor: pointer;
    transition: all 0.2s;
    letter-spacing: 0.05em;
  }
  .panic-btn:hover {
    background: linear-gradient(135deg, #ef444425, #dc262625);
    border-color: #ef444455;
  }
  .panic-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .panic-btn.active {
    background: #ef4444;
    color: white;
    border-color: #ef4444;
    animation: pulse 1.5s ease infinite;
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

  @media (max-width: 1024px) {
    .primary-stats {
      grid-template-columns: 1fr;
    }
    .simple-body {
      grid-template-columns: 1fr;
    }
    .stats-grid {
      grid-template-columns: repeat(2, 1fr);
    }
    .adv-grid {
      grid-template-columns: 1fr;
    }
    .detail-grid {
      grid-template-columns: repeat(2, 1fr);
    }
  }
</style>
