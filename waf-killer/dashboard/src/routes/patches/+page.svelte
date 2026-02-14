<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import type { VirtualPatch } from "$lib/types";

    let patches: VirtualPatch[] = [];
    let loading = true;
    let error: string | null = null;

    onMount(async () => {
        try {
            patches = await api.getVirtualPatches();
        } catch (e) {
            error =
                e instanceof Error
                    ? e.message
                    : "Failed to load Virtual Patches";
            console.error("Virtual Patches load error:", e);
        } finally {
            loading = false;
        }
    });

    function getSeverityColor(severity: string): string {
        switch (severity?.toUpperCase()) {
            case "CRITICAL":
                return "text-red-500 bg-red-950/30 border-red-900/50";
            case "HIGH":
                return "text-orange-500 bg-orange-950/30 border-orange-900/50";
            case "MEDIUM":
                return "text-yellow-500 bg-yellow-950/30 border-yellow-900/50";
            default:
                return "text-blue-500 bg-blue-950/30 border-blue-900/50";
        }
    }
</script>

<div class="space-y-6 container mx-auto p-6">
    <div class="flex justify-between items-center">
        <h1
            class="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-500 to-purple-500"
        >
            Virtual Patches
        </h1>
        <div class="flex space-x-2">
            <button
                class="px-3 py-1 bg-zinc-800 text-xs rounded hover:bg-zinc-700 transition-colors"
                >Generate from CVE</button
            >
        </div>
    </div>

    {#if loading}
        <div class="animate-pulse space-y-4">
            <div
                class="h-12 bg-zinc-900/50 rounded border border-zinc-800"
            ></div>
            <div
                class="h-12 bg-zinc-900/50 rounded border border-zinc-800"
            ></div>
        </div>
    {:else if error}
        <div
            class="p-4 bg-red-900/20 text-red-400 border border-red-900/50 rounded-lg"
        >
            {error}
        </div>
    {:else if patches.length === 0}
        <div
            class="text-center py-12 text-zinc-500 bg-zinc-900/20 rounded-lg border border-zinc-800 border-dashed"
        >
            No virtual patches configured. Generate one from a CVE.
        </div>
    {:else}
        <div
            class="card p-4 table-container border border-zinc-800 rounded-lg bg-black/40"
        >
            <table class="w-full text-left text-sm">
                <thead>
                    <tr class="text-zinc-500 border-b border-zinc-800">
                        <th class="p-3">CVE</th>
                        <th class="p-3">Title</th>
                        <th class="p-3">Severity</th>
                        <th class="p-3">Status</th>
                        <th class="p-3">Created</th>
                        <th class="p-3">Blocks</th>
                        <th class="p-3">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-zinc-800">
                    {#each patches as patch}
                        <tr class="hover:bg-zinc-900/30">
                            <td class="p-3"
                                ><code class="text-shibuya-neon font-mono"
                                    >{patch.cve_id}</code
                                ></td
                            >
                            <td class="p-3 text-zinc-300">{patch.title}</td>
                            <td class="p-3"
                                ><span
                                    class={`px-2 py-0.5 text-xs font-mono rounded border ${getSeverityColor(patch.severity)}`}
                                    >{patch.severity}</span
                                ></td
                            >
                            <td class="p-3"
                                ><span
                                    class="px-2 py-0.5 text-xs rounded {patch.status ===
                                    'active'
                                        ? 'bg-green-900/30 text-green-400'
                                        : 'bg-zinc-800 text-zinc-400'}"
                                    >{patch.status}</span
                                ></td
                            >
                            <td class="p-3 text-zinc-500"
                                >{new Date(
                                    patch.created_at,
                                ).toLocaleDateString()}</td
                            >
                            <td class="p-3 text-zinc-400 font-mono"
                                >{patch.blocks_count}</td
                            >
                            <td class="p-3">
                                <button
                                    class="text-xs text-blue-400 hover:text-white transition-colors"
                                    >Details</button
                                >
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}
</div>
