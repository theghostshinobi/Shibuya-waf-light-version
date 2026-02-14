<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { api } from "$lib/api/client";
    import type { Vulnerability } from "$lib/types";
    import { fade } from "svelte/transition";
    import {
        Download,
        ShieldAlert,
        AlertTriangle,
        AlertCircle,
        Info,
        Upload,
        Plus,
        X,
    } from "lucide-svelte";

    let vulns: Vulnerability[] = [];
    let loading = true;
    let isScanning = false;
    let error: string | null = null;
    let interval: any;

    // Import state
    let showImportModal = false;
    let importJson = "";
    let importing = false;
    let importResult: any = null;

    // Create state
    let showCreateModal = false;
    let creating = false;
    let newVuln = {
        title: "",
        severity: "medium",
        description: "",
        affected_path: "",
    };
    let createMsg = "";

    // Computed stats
    $: totalCount = vulns.length;
    $: criticalCount = vulns.filter(
        (v) => v.severity.toUpperCase() === "CRITICAL",
    ).length;
    $: highCount = vulns.filter(
        (v) => v.severity.toUpperCase() === "HIGH",
    ).length;
    $: openCount = vulns.filter((v) => v.status === "OPEN").length;

    async function loadVulns() {
        try {
            vulns = await api.getVulnerabilities();
        } catch (e) {
            error = "Failed to load Vulnerabilities";
            console.error(e);
        } finally {
            loading = false;
        }
    }

    onMount(loadVulns);

    async function startScan() {
        isScanning = true;
        error = null;
        try {
            await api.startScan();

            // Poll for results
            let attempts = 0;
            const maxAttempts = 10;
            const initialCount = vulns.length;

            interval = setInterval(async () => {
                attempts++;
                await loadVulns();

                if (vulns.length > initialCount || attempts >= maxAttempts) {
                    clearInterval(interval);
                    isScanning = false;
                    if (vulns.length > initialCount) {
                        // Success toast or sound could go here
                    }
                }
            }, 1000);
        } catch (e) {
            error = "Scan failed to start";
            console.error(e);
            isScanning = false;
        }
    }

    onDestroy(() => {
        if (interval) clearInterval(interval);
    });

    function exportJson() {
        const dataStr = JSON.stringify(vulns, null, 2);
        const blob = new Blob([dataStr], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `vulnerabilities_${new Date().toISOString().split("T")[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function getSeverityColor(sev: string): string {
        switch (sev.toLowerCase()) {
            case "critical":
                return "text-red-500 bg-red-950/30 border-red-900/50";
            case "high":
                return "text-orange-500 bg-orange-950/30 border-orange-900/50";
            case "medium":
                return "text-yellow-500 bg-yellow-950/30 border-yellow-900/50";
            default:
                return "text-blue-500 bg-blue-950/30 border-blue-900/50";
        }
    }

    async function importVulnerabilities() {
        importing = true;
        importResult = null;
        try {
            const parsed = JSON.parse(importJson);
            const vulnArray = Array.isArray(parsed) ? parsed : [parsed];
            importResult = await api.importVulnerabilities(
                vulnArray,
                "manual-import",
            );
            await loadVulns();
        } catch (e: any) {
            importResult = { errors: [e.message] };
        } finally {
            importing = false;
        }
    }

    async function createVulnerability() {
        if (!newVuln.title || !newVuln.description) return;
        creating = true;
        createMsg = "";
        try {
            await api.createVulnerability(newVuln);
            createMsg = "✅ Vulnerability created";
            newVuln = {
                title: "",
                severity: "medium",
                description: "",
                affected_path: "",
            };
            await loadVulns();
            setTimeout(() => {
                showCreateModal = false;
                createMsg = "";
            }, 1500);
        } catch (e: any) {
            createMsg = "❌ " + e.message;
        } finally {
            creating = false;
        }
    }
</script>

<div class="space-y-6">
    <div class="flex items-center justify-between">
        <div>
            <h1
                class="text-2xl font-bold tracking-tight flex items-center gap-3"
            >
                <ShieldAlert class="text-red-500" size={28} />
                Vulnerabilities
            </h1>
            <p class="text-zinc-400 mt-1">
                Active CVEs and security flaws detected in your application.
            </p>
        </div>
        <div class="flex items-center gap-3">
            <button
                on:click={() => (showCreateModal = true)}
                class="px-3 py-2 bg-emerald-700 text-emerald-100 font-medium text-sm rounded hover:bg-emerald-600 transition-colors flex items-center gap-2"
            >
                <Plus size={16} />
                Add Vuln
            </button>
            <button
                on:click={() => (showImportModal = true)}
                class="px-3 py-2 bg-indigo-700 text-indigo-100 font-medium text-sm rounded hover:bg-indigo-600 transition-colors flex items-center gap-2"
            >
                <Upload size={16} />
                Import JSON
            </button>
            {#if vulns.length > 0}
                <button
                    on:click={exportJson}
                    class="px-3 py-2 bg-zinc-800 text-zinc-300 font-medium text-sm rounded hover:bg-zinc-700 transition-colors flex items-center gap-2"
                >
                    <Download size={16} />
                    Export JSON
                </button>
            {/if}
            <button
                on:click={startScan}
                disabled={isScanning}
                class="px-4 py-2 bg-white text-black font-medium text-sm rounded hover:bg-zinc-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {isScanning ? "Scanning..." : "Start New Scan"}
            </button>
        </div>
    </div>

    <!-- Stats Bar -->
    {#if !loading && vulns.length > 0}
        <div class="flex gap-4 flex-wrap" in:fade>
            <div
                class="px-4 py-2 bg-zinc-900/50 rounded-lg border border-zinc-800 flex items-center gap-2"
            >
                <span class="text-zinc-400 text-sm">Total:</span>
                <span class="font-bold text-white">{totalCount}</span>
            </div>
            {#if criticalCount > 0}
                <div
                    class="px-4 py-2 bg-red-900/20 rounded-lg border border-red-900/50 flex items-center gap-2"
                >
                    <AlertTriangle size={16} class="text-red-500" />
                    <span class="text-red-400 text-sm">Critical:</span>
                    <span class="font-bold text-red-400">{criticalCount}</span>
                </div>
            {/if}
            {#if highCount > 0}
                <div
                    class="px-4 py-2 bg-orange-900/20 rounded-lg border border-orange-900/50 flex items-center gap-2"
                >
                    <AlertCircle size={16} class="text-orange-500" />
                    <span class="text-orange-400 text-sm">High:</span>
                    <span class="font-bold text-orange-400">{highCount}</span>
                </div>
            {/if}
            <div
                class="px-4 py-2 bg-zinc-900/50 rounded-lg border border-zinc-800 flex items-center gap-2"
            >
                <span class="text-zinc-400 text-sm">Open:</span>
                <span class="font-bold text-yellow-400">{openCount}</span>
            </div>
        </div>
    {/if}

    {#if loading || isScanning}
        <div class="space-y-4">
            <div
                class="flex items-center justify-center h-40 bg-zinc-900/50 rounded-lg border border-zinc-800"
            >
                <div class="text-center space-y-2">
                    <div
                        class="animate-spin w-6 h-6 border-2 border-white border-t-transparent rounded-full mx-auto"
                    ></div>
                    <p class="text-zinc-400">Running Vulnerability Scan...</p>
                </div>
            </div>
        </div>
    {:else if error}
        <div
            class="p-4 bg-red-900/20 text-red-400 border border-red-900/50 rounded-lg"
        >
            {error}
        </div>
    {:else if vulns.length === 0}
        <div
            class="text-center py-12 text-zinc-500 bg-zinc-900/20 rounded-lg border border-zinc-800 border-dashed"
        >
            No vulnerabilities detected. Start a scan.
        </div>
    {:else}
        <div class="grid gap-4">
            {#each vulns as vuln}
                <div
                    in:fade
                    class="group relative p-6 rounded-lg border border-zinc-800 bg-black/40 hover:bg-zinc-900/20 transition-all"
                >
                    <div class="flex items-start justify-between">
                        <div class="space-y-2">
                            <div class="flex items-center gap-3">
                                <span
                                    class={`px-2 py-0.5 text-xs font-mono rounded border ${getSeverityColor(vuln.severity)}`}
                                >
                                    {vuln.severity.toUpperCase()}
                                </span>
                                <h3 class="font-medium text-zinc-100">
                                    {vuln.title}
                                </h3>
                                {#if vuln.cve_id}
                                    <span
                                        class="text-xs text-zinc-500 font-mono bg-zinc-900 px-2 py-0.5 rounded"
                                    >
                                        {vuln.cve_id}
                                    </span>
                                {/if}
                            </div>
                            <p class="text-zinc-400 text-sm">
                                {vuln.description}
                                {#if vuln.affected_path}
                                    <span
                                        class="block mt-1 font-mono text-xs text-zinc-500"
                                        >Path: {vuln.affected_path}</span
                                    >
                                {/if}
                            </p>
                        </div>
                        <div class="flex items-center gap-4">
                            <div class="text-right">
                                <span
                                    class={`text-xs px-2 py-1 rounded-full ${vuln.status === "FIXED" ? "text-green-400 bg-green-900/20" : "text-red-400 bg-red-900/20"}`}
                                >
                                    {vuln.status}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            {/each}
        </div>
    {/if}
</div>

<!-- Import Vulnerabilities Modal -->
{#if showImportModal}
    <div
        class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        on:click|self={() => (showImportModal = false)}
    >
        <div
            class="bg-zinc-900 border border-zinc-700 rounded-xl p-6 w-full max-w-2xl shadow-2xl space-y-4"
        >
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-bold text-white">
                    Import Vulnerabilities (JSON)
                </h2>
                <button
                    on:click={() => (showImportModal = false)}
                    class="text-zinc-400 hover:text-white"
                    ><X size={20} /></button
                >
            </div>
            <p class="text-sm text-zinc-400">
                Paste a JSON array of vulnerability objects. Each object should
                have: title, severity, description, affected_path (optional).
            </p>
            <textarea
                bind:value={importJson}
                rows="10"
                class="w-full bg-black/40 border border-zinc-700 rounded-lg p-3 text-sm font-mono text-zinc-300 focus:outline-none focus:border-indigo-500 resize-y"
                placeholder={'[{"title": "XSS in /search", "severity": "high", "description": "Reflected XSS..."}]'}
            ></textarea>
            {#if importResult}
                <div
                    class="text-sm {importResult.errors
                        ? 'text-red-400'
                        : 'text-green-400'}"
                >
                    {#if importResult.errors}
                        ❌ {importResult.errors.join(", ")}
                    {:else}
                        ✅ Imported {importResult.imported || "successfully"}
                    {/if}
                </div>
            {/if}
            <div class="flex justify-end gap-3">
                <button
                    on:click={() => (showImportModal = false)}
                    class="px-4 py-2 text-sm text-zinc-400 hover:text-white"
                    >Cancel</button
                >
                <button
                    on:click={importVulnerabilities}
                    disabled={importing || !importJson.trim()}
                    class="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {importing ? "Importing..." : "Import"}
                </button>
            </div>
        </div>
    </div>
{/if}

<!-- Create Vulnerability Modal -->
{#if showCreateModal}
    <div
        class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        on:click|self={() => (showCreateModal = false)}
    >
        <div
            class="bg-zinc-900 border border-zinc-700 rounded-xl p-6 w-full max-w-lg shadow-2xl space-y-4"
        >
            <div class="flex justify-between items-center">
                <h2 class="text-lg font-bold text-white">
                    Create Vulnerability
                </h2>
                <button
                    on:click={() => (showCreateModal = false)}
                    class="text-zinc-400 hover:text-white"
                    ><X size={20} /></button
                >
            </div>
            {#if createMsg}
                <div
                    class="text-sm {createMsg.startsWith('✅')
                        ? 'text-green-400'
                        : 'text-red-400'}"
                >
                    {createMsg}
                </div>
            {/if}
            <div class="space-y-3">
                <input
                    bind:value={newVuln.title}
                    placeholder="Title *"
                    class="w-full bg-black/40 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500"
                />
                <select
                    bind:value={newVuln.severity}
                    class="w-full bg-black/40 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200"
                >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <textarea
                    bind:value={newVuln.description}
                    rows="3"
                    placeholder="Description *"
                    class="w-full bg-black/40 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500 resize-y"
                ></textarea>
                <input
                    bind:value={newVuln.affected_path}
                    placeholder="Affected Path (optional, e.g. /api/users)"
                    class="w-full bg-black/40 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-emerald-500"
                />
            </div>
            <div class="flex justify-end gap-3">
                <button
                    on:click={() => (showCreateModal = false)}
                    class="px-4 py-2 text-sm text-zinc-400 hover:text-white"
                    >Cancel</button
                >
                <button
                    on:click={createVulnerability}
                    disabled={creating ||
                        !newVuln.title ||
                        !newVuln.description}
                    class="px-4 py-2 bg-emerald-600 text-white text-sm font-medium rounded-lg hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                    {creating ? "Creating..." : "Create"}
                </button>
            </div>
        </div>
    </div>
{/if}
