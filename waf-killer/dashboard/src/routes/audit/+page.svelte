<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { api } from "$lib/api/client";
    import type { RequestLog } from "$lib/types";
    import {
        Activity,
        Search,
        Pause,
        Play,
        ChevronDown,
        ChevronRight,
        Shield,
        Globe,
        Clock,
        FileText,
        Code,
        Download,
    } from "lucide-svelte";
    import { fade, slide } from "svelte/transition";

    let logs: RequestLog[] = [];
    let interval: any;
    let isPaused = false;
    let searchTerm = "";
    let expandedRows = new Set<string>();

    async function fetchLogs() {
        if (isPaused) return;
        try {
            logs = await api.getLogs();
        } catch (e) {
            console.error("Failed to fetch logs", e);
        }
    }

    function toggleRow(id: string) {
        if (expandedRows.has(id)) {
            expandedRows.delete(id);
        } else {
            expandedRows.add(id);
        }
        expandedRows = expandedRows; // Trigger reactivity
    }

    onMount(() => {
        fetchLogs();
        interval = setInterval(fetchLogs, 2000);
    });

    onDestroy(() => {
        if (interval) clearInterval(interval);
    });

    $: filteredLogs = logs.filter(
        (l) =>
            l.uri.toLowerCase().includes(searchTerm.toLowerCase()) ||
            l.client_ip.includes(searchTerm) ||
            l.reason.toLowerCase().includes(searchTerm.toLowerCase()) ||
            l.method.toLowerCase().includes(searchTerm.toLowerCase()),
    );

    function getStatusColor(status: number) {
        if (status >= 500) return "text-red-500";
        if (status >= 400) return "text-yellow-500";
        if (status >= 300) return "text-blue-500";
        return "text-green-500";
    }

    function getActionBadge(action: string) {
        switch (action) {
            case "Block":
                return "bg-red-500/20 text-red-400 border-red-500/30";
            case "Challenge":
                return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
            default:
                return "bg-green-500/20 text-green-400 border-green-500/30";
        }
    }

    async function exportLogs() {
        try {
            const now = new Date();
            const dayAgo = new Date(now.getTime() - 86400000);
            const blob = await api.exportAuditLog(
                dayAgo.toISOString(),
                now.toISOString(),
            );
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `audit_logs_${now.toISOString().split("T")[0]}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            console.error("Export failed", e);
        }
    }
</script>

<div class="space-y-6 p-6">
    <div class="flex justify-between items-center">
        <div>
            <h2
                class="text-3xl font-bold tracking-tight text-white flex items-center gap-2"
            >
                <Shield class="text-blue-500" /> Audit Logs
            </h2>
            <p class="text-slate-400">Detailed inspection of WAF traffic</p>
        </div>

        <div class="flex items-center gap-4">
            <div class="relative">
                <Search
                    class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                    size={16}
                />
                <input
                    type="text"
                    bind:value={searchTerm}
                    placeholder="Search logs..."
                    class="bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-blue-500 w-64 transition-colors"
                />
            </div>

            <button
                on:click={exportLogs}
                class="p-2 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors text-slate-300 flex items-center gap-2"
                title="Export last 24h"
            >
                <Download size={16} />
                <span class="text-sm">Export</span>
            </button>

            <button
                on:click={() => (isPaused = !isPaused)}
                class="p-2 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors text-slate-300"
                title={isPaused ? "Resume" : "Pause"}
            >
                {#if isPaused}
                    <Play size={20} />
                {:else}
                    <Pause size={20} />
                {/if}
            </button>
        </div>
    </div>

    <div
        class="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-xl"
    >
        <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
                <thead
                    class="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-medium"
                >
                    <tr>
                        <th class="px-6 py-4 w-10"></th>
                        <th class="px-6 py-4">Time</th>
                        <th class="px-6 py-4">Method</th>
                        <th class="px-6 py-4">Status</th>
                        <th class="px-6 py-4">Source</th>
                        <th class="px-6 py-4">URI</th>
                        <th class="px-6 py-4">Action</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-slate-800/50">
                    {#each filteredLogs as log (log.id)}
                        <tr
                            class="hover:bg-slate-800/30 transition-colors cursor-pointer {expandedRows.has(
                                log.id,
                            )
                                ? 'bg-slate-800/50'
                                : ''}"
                            on:click={() => toggleRow(log.id)}
                        >
                            <td class="px-6 py-4 text-slate-500">
                                {#if expandedRows.has(log.id)}
                                    <ChevronDown size={16} />
                                {:else}
                                    <ChevronRight size={16} />
                                {/if}
                            </td>
                            <td
                                class="px-6 py-4 font-mono text-slate-400 whitespace-nowrap"
                            >
                                <div class="flex items-center gap-2">
                                    <Clock size={14} />
                                    {new Date(
                                        log.timestamp * 1000,
                                    ).toLocaleTimeString("en-US")}
                                </div>
                            </td>
                            <td class="px-6 py-4">
                                <span
                                    class="font-bold font-mono {log.method ===
                                    'GET'
                                        ? 'text-blue-400'
                                        : 'text-purple-400'}"
                                >
                                    {log.method}
                                </span>
                            </td>
                            <td
                                class="px-6 py-4 font-bold {getStatusColor(
                                    log.status,
                                )}"
                            >
                                {log.status}
                            </td>
                            <td class="px-6 py-4 text-slate-300">
                                <div class="flex flex-col">
                                    <span class="font-mono"
                                        >{log.client_ip}</span
                                    >
                                    <span
                                        class="text-xs text-slate-500 flex items-center gap-1"
                                    >
                                        <Globe size={10} />
                                        {log.country || "Unknown"}
                                    </span>
                                </div>
                            </td>
                            <td
                                class="px-6 py-4 text-slate-300 max-w-md truncate"
                                title={log.uri}
                            >
                                {log.uri}
                            </td>
                            <td class="px-6 py-4">
                                <span
                                    class="px-2 py-1 rounded-full text-xs font-medium border {getActionBadge(
                                        log.action,
                                    )}"
                                >
                                    {log.action}
                                </span>
                                {#if log.reason && log.reason !== "Passed"}
                                    <div
                                        class="text-xs text-slate-500 mt-1 truncate max-w-[150px]"
                                        title={log.reason}
                                    >
                                        {log.reason}
                                    </div>
                                {/if}
                            </td>
                        </tr>

                        {#if expandedRows.has(log.id)}
                            <tr transition:slide={{ duration: 200 }}>
                                <td
                                    colspan="7"
                                    class="bg-slate-900/80 p-6 shadow-inner border-b border-slate-800"
                                >
                                    <!-- Attack/Defense Recap -->
                                    <div
                                        class="mb-6 bg-slate-950/50 rounded-lg border border-slate-800 p-4"
                                    >
                                        <h3
                                            class="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2"
                                        >
                                            <Shield
                                                size={16}
                                                class="text-blue-400"
                                            /> Defense Analysis
                                        </h3>
                                        <div
                                            class="flex flex-wrap items-center gap-6"
                                        >
                                            <!-- Primary Engine -->
                                            <div class="flex flex-col gap-1">
                                                <span
                                                    class="text-xs text-slate-500 uppercase font-mono"
                                                    >Engine</span
                                                >
                                                <div
                                                    class="flex items-center gap-2"
                                                >
                                                    {#if log.reason
                                                        ?.toLowerCase()
                                                        .includes("ml")}
                                                        <span
                                                            class="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-bold"
                                                            >ML Engine</span
                                                        >
                                                    {:else if log.reason
                                                        ?.toLowerCase()
                                                        .includes("rule") || log.reason?.includes("Grimoire") || log.reason?.includes("CRS")}
                                                        <span
                                                            class="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs font-bold"
                                                            >WAF (CRS)</span
                                                        >
                                                    {:else if log.reason
                                                        ?.toLowerCase()
                                                        .includes("threat") || log.reason
                                                            ?.toLowerCase()
                                                            .includes("blacklist")}
                                                        <span
                                                            class="px-2 py-1 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs font-bold"
                                                            >Threat Intel</span
                                                        >
                                                    {:else}
                                                        <span
                                                            class="px-2 py-1 bg-slate-700/50 text-slate-400 border border-slate-700 rounded text-xs font-bold"
                                                            >Standard</span
                                                        >
                                                    {/if}
                                                </div>
                                            </div>

                                            <!-- Scores -->
                                            {#if log.ml_score !== undefined}
                                                <div
                                                    class="flex flex-col gap-1"
                                                >
                                                    <span
                                                        class="text-xs text-slate-500 uppercase font-mono"
                                                        >ML Confidence</span
                                                    >
                                                    <div
                                                        class="flex items-center gap-2"
                                                    >
                                                        <div
                                                            class="w-24 h-2 bg-slate-800 rounded-full overflow-hidden"
                                                        >
                                                            <div
                                                                class="h-full {log.ml_score >
                                                                0.8
                                                                    ? 'bg-red-500'
                                                                    : log.ml_score >
                                                                        0.5
                                                                      ? 'bg-yellow-500'
                                                                      : 'bg-green-500'}"
                                                                style="width: {log.ml_score *
                                                                    100}%"
                                                            ></div>
                                                        </div>
                                                        <span
                                                            class="text-xs font-mono text-slate-300"
                                                            >{(
                                                                log.ml_score *
                                                                100
                                                            ).toFixed(1)}%</span
                                                        >
                                                    </div>
                                                </div>
                                            {/if}

                                            {#if log.crs_score !== undefined}
                                                <div
                                                    class="flex flex-col gap-1"
                                                >
                                                    <span
                                                        class="text-xs text-slate-500 uppercase font-mono"
                                                        >Anomaly Score</span
                                                    >
                                                    <span
                                                        class="text-sm font-mono text-slate-300"
                                                        >{log.crs_score}</span
                                                    >
                                                </div>
                                            {/if}

                                            <!-- Reason -->
                                            <div
                                                class="flex flex-col gap-1 flex-1"
                                            >
                                                <span
                                                    class="text-xs text-slate-500 uppercase font-mono"
                                                    >Trigger</span
                                                >
                                                <span
                                                    class="text-sm text-slate-300 font-mono break-all"
                                                    >{log.reason || "N/A"}</span
                                                >
                                            </div>
                                        </div>
                                    </div>

                                    <div
                                        class="grid grid-cols-1 md:grid-cols-2 gap-6"
                                    >
                                        <!-- Request Details -->
                                        <div class="space-y-4">
                                            <h3
                                                class="text-sm font-semibold text-slate-300 flex items-center gap-2"
                                            >
                                                <FileText size={16} /> Request Headers
                                            </h3>
                                            <div
                                                class="bg-slate-950 rounded-lg border border-slate-800 p-4 font-mono text-xs overflow-x-auto"
                                            >
                                                {#if log.headers && log.headers.length > 0}
                                                    <table class="w-full">
                                                        {#each log.headers as [key, value]}
                                                            <tr>
                                                                <td
                                                                    class="text-blue-400 pr-4 py-1 select-none"
                                                                    >{key}:</td
                                                                >
                                                                <td
                                                                    class="text-slate-300 py-1 break-all"
                                                                    >{value}</td
                                                                >
                                                            </tr>
                                                        {/each}
                                                    </table>
                                                {:else}
                                                    <span
                                                        class="text-slate-500 italic"
                                                        >No headers captured</span
                                                    >
                                                {/if}
                                            </div>
                                        </div>

                                        <!-- Body / Payload -->
                                        <div class="space-y-4">
                                            <h3
                                                class="text-sm font-semibold text-slate-300 flex items-center gap-2"
                                            >
                                                <Code size={16} /> Request Body /
                                                Payload
                                            </h3>
                                            <div
                                                class="bg-slate-950 rounded-lg border border-slate-800 p-4 font-mono text-xs text-slate-300 overflow-x-auto min-h-[100px]"
                                            >
                                                {#if log.body}
                                                    <pre
                                                        class="whitespace-pre-wrap">{log.body}</pre>
                                                {:else}
                                                    <span
                                                        class="text-slate-500 italic"
                                                        >No body content
                                                        captured</span
                                                    >
                                                {/if}
                                            </div>

                                            {#if log.ml_features}
                                                <h3
                                                    class="text-sm font-semibold text-slate-300 flex items-center gap-2 mt-4"
                                                >
                                                    <Activity size={16} /> ML Features
                                                </h3>
                                                <div
                                                    class="bg-slate-950 rounded-lg border border-slate-800 p-4 font-mono text-xs text-slate-400 overflow-x-auto"
                                                >
                                                    {log.ml_features}
                                                </div>
                                            {/if}
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        {/if}
                    {:else}
                        <tr>
                            <td
                                colspan="7"
                                class="px-6 py-12 text-center text-slate-500"
                            >
                                <div class="flex flex-col items-center gap-2">
                                    <Activity size={32} class="opacity-20" />
                                    <p>No traffic recorded yet</p>
                                </div>
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    </div>
</div>
