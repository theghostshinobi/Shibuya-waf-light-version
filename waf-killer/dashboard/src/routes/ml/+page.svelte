<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { api } from "$lib/api/client";
    import {
        Brain,
        Cpu,
        Zap,
        Activity,
        Shield,
        Target,
        BarChart3,
        AlertTriangle,
        Check,
        X,
    } from "lucide-svelte";

    let enabled = false;
    let statusLoaded = false;
    let threshold = 0.7;
    let pollInterval: any;

    // ML Stats
    let stats: any = {
        predictions: 0,
        detections: 0,
        detection_rate: 0,
        last_attack_type: "None",
        avg_inference_us: 0,
        threshold: 0.7,
        distribution: {},
        last_confidence: 0,
    };

    // Recent detections
    let detections: any[] = [];

    // Model info
    let modelInfo: any = null;

    // Animation state
    let pulseOpacity = 0.3;
    let neuralNodes: { x: number; y: number; active: boolean }[] = [];

    const ATTACK_COLORS: Record<string, string> = {
        SQLi: "#ef4444",
        XSS: "#f97316",
        RCE: "#dc2626",
        "Path Traversal": "#eab308",
        "Command Injection": "#b91c1c",
        SSRF: "#8b5cf6",
        XXE: "#6366f1",
        SSTI: "#ec4899",
        NoSQLi: "#14b8a6",
        Benign: "#22c55e",
    };

    const SEVERITY_COLORS: Record<string, string> = {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
        none: "#64748b",
    };

    function initNeuralNodes() {
        neuralNodes = Array.from({ length: 24 }, (_, i) => ({
            x: 15 + (i % 6) * 14,
            y: 15 + Math.floor(i / 6) * 20,
            active: Math.random() > 0.5,
        }));
    }

    async function loadStatus() {
        try {
            const status = await api.getModuleStatus("ml");
            enabled = status.enabled;
            statusLoaded = true;
        } catch (e) {
            console.error("Failed to load ML status", e);
            enabled = true;
            statusLoaded = true;
        }
    }

    async function updateAll() {
        try {
            const [mlStats, mlDetections, mlModel] = await Promise.all([
                api.getMLStats(),
                api.getMLRecentDetections(),
                api.getMLModelInfo(),
            ]);
            stats = mlStats;
            threshold = mlStats.threshold || 0.7;
            detections = mlDetections.detections || [];
            modelInfo = mlModel;

            // Animate neural nodes
            neuralNodes = neuralNodes.map((n) => ({
                ...n,
                active: stats.predictions > 0 ? Math.random() > 0.4 : false,
            }));
            pulseOpacity = stats.detections > 0 ? 0.6 : 0.2;
        } catch (e) {
            console.error(e);
        }
    }

    async function toggle() {
        try {
            const res = await api.toggleModule("ml");
            enabled = res.enabled;
        } catch (e) {
            console.error(e);
        }
    }

    async function updateThreshold() {
        try {
            const res = await api.updateMLThreshold(threshold);
            if (res.success) {
                console.log("ML threshold updated:", res.message);
            }
        } catch (e) {
            console.error("Failed to update ML threshold", e);
        }
    }

    function formatTime(ts: number): string {
        if (!ts) return "--";
        return new Date(ts * 1000).toLocaleTimeString();
    }

    function getDistributionEntries(): [string, number][] {
        if (!stats.distribution) return [];
        return (Object.entries(stats.distribution) as [string, number][]).sort(
            ([, a], [, b]) => b - a,
        );
    }

    function getMaxDistribution(): number {
        const entries = getDistributionEntries();
        if (entries.length === 0) return 1;
        return Math.max(...entries.map(([, v]) => v as number));
    }

    onMount(async () => {
        initNeuralNodes();
        await loadStatus();
        await updateAll();
        pollInterval = setInterval(updateAll, 2000);
    });

    onDestroy(() => {
        if (pollInterval) clearInterval(pollInterval);
    });
</script>

<!-- Page Header -->
<div class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-3xl font-bold text-white flex items-center gap-3">
                <Brain class="text-yellow-500" size={36} />
                Neural Engine
            </h1>
            <p class="text-slate-400 mt-1">
                ML-powered threat classification &amp; anomaly detection
            </p>
        </div>
        <button
            on:click={toggle}
            class="px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-300
            {enabled
                ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40 hover:bg-yellow-500/30'
                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:bg-slate-700'}"
        >
            {enabled ? "ENGINE ONLINE" : "ENGINE OFFLINE"}
        </button>
    </div>

    <!-- ════════ Stats Grid ════════ -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div class="stat-card">
            <div class="stat-icon bg-yellow-500/10">
                <Cpu class="text-yellow-500" size={20} />
            </div>
            <div class="stat-value">
                {stats.predictions?.toLocaleString() || 0}
            </div>
            <div class="stat-label">Predictions</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon bg-red-500/10">
                <Shield class="text-red-400" size={20} />
            </div>
            <div class="stat-value text-red-400">
                {stats.detections?.toLocaleString() || 0}
            </div>
            <div class="stat-label">Threats Detected</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon bg-blue-500/10">
                <Target class="text-blue-400" size={20} />
            </div>
            <div class="stat-value">
                {stats.detection_rate?.toFixed(1) || 0}%
            </div>
            <div class="stat-label">Detection Rate</div>
        </div>
        <div class="stat-card">
            <div class="stat-icon bg-green-500/10">
                <Zap class="text-green-400" size={20} />
            </div>
            <div class="stat-value">
                {stats.avg_inference_us?.toFixed(0) || 0}µs
            </div>
            <div class="stat-label">Avg Inference</div>
        </div>
    </div>

    <!-- ════════ Main Content Grid ════════ -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Col 1: Neural Network Viz + Threshold -->
        <div class="space-y-6">
            <!-- Neural Visualization -->
            <div class="panel p-6">
                <h3
                    class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4"
                >
                    Neural Activity
                </h3>
                <div
                    class="relative w-full aspect-square rounded-2xl overflow-hidden bg-slate-950"
                >
                    <!-- Glow effect -->
                    <div
                        class="absolute inset-0 bg-gradient-radial from-yellow-500/10 to-transparent transition-opacity duration-1000"
                        style="opacity: {pulseOpacity}"
                    ></div>

                    <!-- Neural nodes -->
                    <svg viewBox="0 0 100 100" class="w-full h-full">
                        <!-- Connection lines -->
                        {#each neuralNodes as node, i}
                            {#each neuralNodes as target, j}
                                {#if j > i && Math.abs(node.x - target.x) < 20 && Math.abs(node.y - target.y) < 25}
                                    <line
                                        x1={node.x}
                                        y1={node.y}
                                        x2={target.x}
                                        y2={target.y}
                                        stroke={node.active && target.active
                                            ? "#eab308"
                                            : "#334155"}
                                        stroke-width="0.3"
                                        opacity={node.active && target.active
                                            ? 0.6
                                            : 0.2}
                                    />
                                {/if}
                            {/each}
                        {/each}

                        <!-- Nodes -->
                        {#each neuralNodes as node}
                            <circle
                                cx={node.x}
                                cy={node.y}
                                r="2"
                                fill={node.active ? "#eab308" : "#475569"}
                                opacity={node.active ? 0.9 : 0.4}
                                class="transition-all duration-700"
                            />
                            {#if node.active}
                                <circle
                                    cx={node.x}
                                    cy={node.y}
                                    r="4"
                                    fill="none"
                                    stroke="#eab308"
                                    stroke-width="0.3"
                                    opacity="0.3"
                                />
                            {/if}
                        {/each}
                    </svg>

                    <!-- Status overlay -->
                    <div class="absolute bottom-3 left-3 right-3">
                        <div class="flex items-center gap-2 text-xs font-mono">
                            <div
                                class="w-1.5 h-1.5 rounded-full {enabled
                                    ? 'bg-green-500 animate-pulse'
                                    : 'bg-slate-600'}"
                            ></div>
                            <span
                                class={enabled
                                    ? "text-green-400"
                                    : "text-slate-500"}
                            >
                                {enabled ? "INFERENCE ACTIVE" : "OFFLINE"}
                            </span>
                        </div>
                        {#if stats.last_attack_type !== "None" && stats.last_attack_type}
                            <div class="text-xs text-red-400 mt-1 font-mono">
                                Last: {stats.last_attack_type}
                            </div>
                        {/if}
                    </div>
                </div>
            </div>

            <!-- Threshold Slider -->
            <div class="panel p-6">
                <div class="flex justify-between items-center mb-3">
                    <h3
                        class="text-sm font-semibold text-slate-300 uppercase tracking-wider"
                    >
                        Threshold
                    </h3>
                    <span class="text-yellow-500 font-mono font-bold text-lg"
                        >{threshold.toFixed(2)}</span
                    >
                </div>
                <input
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    bind:value={threshold}
                    on:change={updateThreshold}
                    class="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-yellow-500"
                />
                <div class="flex justify-between text-xs text-slate-500 mt-2">
                    <span>Sensitive</span>
                    <span>Strict</span>
                </div>
            </div>

            <!-- Model Info Card -->
            {#if modelInfo}
                <div class="panel p-6">
                    <h3
                        class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4"
                    >
                        Model Info
                    </h3>
                    <div class="space-y-3 text-sm">
                        <div class="flex justify-between">
                            <span class="text-slate-400">Framework</span>
                            <span class="text-white font-mono"
                                >{modelInfo.classifier?.framework ||
                                    "smartcore"}</span
                            >
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-400">Algorithm</span>
                            <span class="text-white font-mono"
                                >{modelInfo.classifier?.type ||
                                    "Random Forest"}</span
                            >
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-400">Trees</span>
                            <span class="text-yellow-400 font-mono"
                                >{modelInfo.classifier?.n_trees || 0}</span
                            >
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-400">Classes</span>
                            <span class="text-yellow-400 font-mono"
                                >{modelInfo.classifier?.n_classes || 0}</span
                            >
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-400">Features</span>
                            <span class="text-white font-mono"
                                >{modelInfo.classifier?.features || 50}</span
                            >
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-400">ONNX Engine</span>
                            <span
                                class="font-mono {modelInfo.onnx?.active
                                    ? 'text-green-400'
                                    : 'text-slate-500'}"
                            >
                                {modelInfo.onnx?.active ? "Active" : "Inactive"}
                            </span>
                        </div>
                    </div>
                </div>
            {/if}
        </div>

        <!-- Col 2: Attack Distribution -->
        <div class="space-y-6">
            <div class="panel p-6">
                <h3
                    class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2"
                >
                    <BarChart3 size={16} class="text-yellow-500" />
                    Attack Classification
                </h3>

                {#if getDistributionEntries().length > 0}
                    <div class="space-y-3">
                        {#each getDistributionEntries() as [type, count]}
                            {@const pct =
                                ((count as number) / getMaxDistribution()) *
                                100}
                            {@const color = ATTACK_COLORS[type] || "#64748b"}
                            <div>
                                <div class="flex justify-between text-sm mb-1">
                                    <span class="text-white font-medium"
                                        >{type}</span
                                    >
                                    <span class="text-slate-400 font-mono"
                                        >{count}</span
                                    >
                                </div>
                                <div
                                    class="w-full h-2 bg-slate-800 rounded-full overflow-hidden"
                                >
                                    <div
                                        class="h-full rounded-full transition-all duration-500"
                                        style="width: {pct}%; background-color: {color};"
                                    ></div>
                                </div>
                            </div>
                        {/each}
                    </div>
                {:else}
                    <div class="text-center py-12">
                        <Activity
                            class="text-slate-600 mx-auto mb-3"
                            size={32}
                        />
                        <p class="text-slate-500 text-sm">
                            No attacks classified yet
                        </p>
                        <p class="text-slate-600 text-xs mt-1">
                            Detections will appear as traffic flows
                        </p>
                    </div>
                {/if}
            </div>

            <!-- Attack Classes -->
            {#if modelInfo?.classifier?.classes}
                <div class="panel p-6">
                    <h3
                        class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4"
                    >
                        Trained Classes
                    </h3>
                    <div class="grid grid-cols-2 gap-2">
                        {#each modelInfo.classifier.classes as cls}
                            {@const color =
                                ATTACK_COLORS[cls.name] || "#64748b"}
                            {@const sevColor =
                                SEVERITY_COLORS[cls.severity] || "#64748b"}
                            <div
                                class="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/50 border border-slate-700/50"
                            >
                                <div
                                    class="w-2 h-2 rounded-full"
                                    style="background-color: {color};"
                                ></div>
                                <span class="text-sm text-white flex-1"
                                    >{cls.name}</span
                                >
                                <span
                                    class="text-[10px] font-mono px-1.5 py-0.5 rounded"
                                    style="color: {sevColor}; background-color: {sevColor}20;"
                                >
                                    {cls.severity}
                                </span>
                            </div>
                        {/each}
                    </div>
                </div>
            {/if}
        </div>

        <!-- Col 3: Live Detection Feed -->
        <div class="panel p-6 max-h-[calc(100vh-260px)] flex flex-col">
            <h3
                class="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2"
            >
                <AlertTriangle size={16} class="text-red-400" />
                Live Detections
                {#if detections.length > 0}
                    <span class="ml-auto text-xs font-mono text-slate-500"
                        >{detections.length}</span
                    >
                {/if}
            </h3>

            <div class="flex-1 overflow-y-auto space-y-3 pr-1 custom-scrollbar">
                {#if detections.length > 0}
                    {#each detections as det}
                        {@const color =
                            ATTACK_COLORS[det.attack_type] || "#64748b"}
                        <div
                            class="p-3 rounded-xl bg-slate-800/50 border border-slate-700/30 hover:border-slate-600/50 transition-colors"
                        >
                            <div class="flex items-center gap-2 mb-2">
                                <span
                                    class="text-xs font-bold px-2 py-0.5 rounded-full"
                                    style="color: {color}; background-color: {color}15; border: 1px solid {color}40;"
                                >
                                    {det.attack_type}
                                </span>
                                <span
                                    class="text-xs text-slate-500 font-mono ml-auto"
                                >
                                    {det.confidence
                                        ? (det.confidence * 100).toFixed(0) +
                                          "%"
                                        : "--"}
                                </span>
                            </div>
                            <div
                                class="text-xs text-slate-300 font-mono truncate"
                            >
                                {det.method}
                                {det.uri}
                            </div>
                            <div class="flex justify-between mt-1">
                                <span class="text-xs text-slate-500"
                                    >{det.client_ip}</span
                                >
                                <span class="text-xs text-slate-600"
                                    >{formatTime(det.timestamp)}</span
                                >
                            </div>
                            <div class="flex items-center gap-1 mt-1">
                                {#if det.action === "Block"}
                                    <X size={12} class="text-red-400" />
                                    <span class="text-xs text-red-400"
                                        >Blocked</span
                                    >
                                {:else}
                                    <AlertTriangle
                                        size={12}
                                        class="text-yellow-400"
                                    />
                                    <span class="text-xs text-yellow-400"
                                        >Shadow</span
                                    >
                                {/if}
                            </div>
                        </div>
                    {/each}
                {:else}
                    <div class="text-center py-16">
                        <Shield class="text-slate-700 mx-auto mb-3" size={40} />
                        <p class="text-slate-500 text-sm">No detections yet</p>
                        <p class="text-slate-600 text-xs mt-1">
                            ML detections will stream here in real-time
                        </p>
                    </div>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
    .stat-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(51, 65, 85, 0.5);
        border-radius: 1rem;
        padding: 1.25rem;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }
    .stat-icon {
        width: 2.25rem;
        height: 2.25rem;
        border-radius: 0.75rem;
        display: flex;
        align-items: center;
        justify-content: center;
    }
    .stat-value {
        font-size: 1.5rem;
        font-weight: 700;
        font-family: ui-monospace, monospace;
        color: white;
    }
    .stat-label {
        font-size: 0.75rem;
        color: rgb(148, 163, 184);
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .panel {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(51, 65, 85, 0.5);
        border-radius: 1rem;
    }
    .custom-scrollbar::-webkit-scrollbar {
        width: 4px;
    }
    .custom-scrollbar::-webkit-scrollbar-track {
        background: transparent;
    }
    .custom-scrollbar::-webkit-scrollbar-thumb {
        background: rgba(100, 116, 139, 0.3);
        border-radius: 2px;
    }
    .bg-gradient-radial {
        background: radial-gradient(
            circle at center,
            var(--tw-gradient-from),
            var(--tw-gradient-to)
        );
    }
</style>
