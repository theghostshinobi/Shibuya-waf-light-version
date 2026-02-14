<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import { Activity, RefreshCw, Copy, Download } from "lucide-svelte";

    let metricsText = "";
    let loading = true;
    let error = "";
    let copied = false;

    onMount(loadMetrics);

    async function loadMetrics() {
        loading = true;
        error = "";
        try {
            metricsText = await api.getMetrics();
        } catch (e: any) {
            error = e.message || "Failed to fetch metrics";
            metricsText = "";
        } finally {
            loading = false;
        }
    }

    function copyToClipboard() {
        navigator.clipboard.writeText(metricsText);
        copied = true;
        setTimeout(() => (copied = false), 2000);
    }

    function downloadMetrics() {
        const blob = new Blob([metricsText], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `metrics_${new Date().toISOString().split("T")[0]}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    }

    // Parse metrics into sections
    $: sections = parseMetrics(metricsText);

    function parseMetrics(text: string) {
        if (!text) return [];
        const lines = text.split("\n");
        const result: Array<{
            name: string;
            help: string;
            type: string;
            values: string[];
        }> = [];
        let current: any = null;

        for (const line of lines) {
            if (line.startsWith("# HELP")) {
                if (current) result.push(current);
                const name = line.split(" ")[2] || "";
                current = {
                    name,
                    help: line.replace(/^# HELP \S+ /, ""),
                    type: "",
                    values: [],
                };
            } else if (line.startsWith("# TYPE")) {
                if (current) current.type = line.split(" ").pop() || "";
            } else if (line.trim() && !line.startsWith("#") && current) {
                current.values.push(line);
            }
        }
        if (current) result.push(current);
        return result;
    }
</script>

<div class="space-y-6 p-6">
    <div class="flex justify-between items-center">
        <div>
            <h1
                class="text-3xl font-bold tracking-tight text-white flex items-center gap-3"
            >
                <Activity class="text-emerald-500" size={32} />
                Prometheus Metrics
            </h1>
            <p class="text-slate-400 mt-1">
                Real-time WAF engine performance and security metrics
            </p>
        </div>
        <div class="flex items-center gap-3">
            <button
                on:click={loadMetrics}
                disabled={loading}
                class="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium flex items-center gap-2 disabled:opacity-50"
            >
                <RefreshCw size={14} class={loading ? "animate-spin" : ""} />
                Refresh
            </button>
            {#if metricsText}
                <button
                    on:click={copyToClipboard}
                    class="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium flex items-center gap-2"
                >
                    <Copy size={14} />
                    {copied ? "Copied!" : "Copy"}
                </button>
                <button
                    on:click={downloadMetrics}
                    class="px-4 py-2 bg-slate-800 text-slate-300 rounded-lg hover:bg-slate-700 transition-colors text-sm font-medium flex items-center gap-2"
                >
                    <Download size={14} />
                    Download
                </button>
            {/if}
        </div>
    </div>

    {#if loading}
        <div class="flex items-center justify-center py-20 text-slate-500">
            <RefreshCw size={24} class="animate-spin mr-3" />
            Loading metrics...
        </div>
    {:else if error}
        <div
            class="bg-red-900/20 border border-red-900/30 rounded-xl p-6 text-red-400"
        >
            <p class="font-medium">Failed to load metrics</p>
            <p class="text-sm mt-1 text-red-500">{error}</p>
        </div>
    {:else if sections.length > 0}
        <div class="grid gap-4">
            {#each sections as section}
                <div
                    class="bg-slate-900/50 border border-slate-800 rounded-xl p-5"
                >
                    <div class="flex items-center justify-between mb-2">
                        <h3
                            class="font-mono text-sm font-bold text-emerald-400"
                        >
                            {section.name}
                        </h3>
                        <span
                            class="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono uppercase"
                            >{section.type}</span
                        >
                    </div>
                    <p class="text-xs text-slate-500 mb-3">{section.help}</p>
                    <div class="space-y-1">
                        {#each section.values as val}
                            <div
                                class="font-mono text-xs text-slate-300 bg-black/30 px-3 py-1.5 rounded"
                            >
                                {val}
                            </div>
                        {/each}
                    </div>
                </div>
            {/each}
        </div>
    {:else}
        <div class="bg-slate-900/50 border border-slate-800 rounded-xl p-8">
            <pre
                class="font-mono text-xs text-slate-400 whitespace-pre-wrap overflow-x-auto max-h-[70vh]">{metricsText ||
                    "No metrics data available"}</pre>
        </div>
    {/if}
</div>
