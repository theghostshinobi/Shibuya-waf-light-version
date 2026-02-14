<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import type { DiscoveredEndpoint } from "$lib/types";
    import {
        Card,
        CardHeader,
        CardTitle,
        CardContent,
    } from "$lib/components/ui/card";
    import { Button } from "$lib/components/ui/button";

    let endpoints: DiscoveredEndpoint[] = [];
    let loading = true;
    let error: string | null = null;

    onMount(async () => {
        try {
            endpoints = await api.getShadowApiEndpoints();
        } catch (e: any) {
            console.error("Failed to load shadow endpoints", e);
            error = e.message;
        } finally {
            loading = false;
        }
    });
</script>

<div class="container mx-auto p-6 space-y-6">
    <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold">Shadow API Discovery</h1>
        <button
            class="px-4 py-2 border rounded hover:bg-neutral-800"
            on:click={() => window.location.reload()}>Refresh</button
        >
    </div>

    {#if loading}
        <div class="flex items-center justify-center h-32">
            <div
                class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"
            ></div>
        </div>
    {:else if error}
        <div class="bg-red-500/10 text-red-500 p-4 rounded-lg">
            Error: {error}
        </div>
    {:else if endpoints.length === 0}
        <Card>
            <CardContent class="p-8 text-center text-muted-foreground">
                No endpoints discovered yet. Generate some traffic!
            </CardContent>
        </Card>
    {:else}
        <Card>
            <CardHeader>
                <CardTitle>Discovered Endpoints ({endpoints.length})</CardTitle>
            </CardHeader>
            <CardContent>
                <div class="rounded-md border border-neutral-800">
                    <table class="w-full text-sm">
                        <thead>
                            <tr
                                class="border-b border-neutral-800 bg-neutral-900/50"
                            >
                                <th
                                    class="h-10 px-4 text-left font-medium text-neutral-400"
                                    >Method</th
                                >
                                <th
                                    class="h-10 px-4 text-left font-medium text-neutral-400"
                                    >Path</th
                                >
                                <th
                                    class="h-10 px-4 text-right font-medium text-neutral-400"
                                    >Hit Count</th
                                >
                                <th
                                    class="h-10 px-4 text-right font-medium text-neutral-400"
                                    >Avg Latency</th
                                >
                                <th
                                    class="h-10 px-4 text-right font-medium text-neutral-400"
                                    >Last Seen</th
                                >
                            </tr>
                        </thead>
                        <tbody>
                            {#each endpoints as endpoint}
                                <tr
                                    class="border-b border-neutral-800 hover:bg-neutral-900/30"
                                >
                                    <td class="p-4 font-mono text-xs">
                                        <span
                                            class={`px-2 py-1 rounded ${
                                                endpoint.method === "GET"
                                                    ? "bg-blue-900/30 text-blue-400"
                                                    : endpoint.method === "POST"
                                                      ? "bg-green-900/30 text-green-400"
                                                      : endpoint.method ===
                                                          "DELETE"
                                                        ? "bg-red-900/30 text-red-400"
                                                        : "bg-neutral-800 text-neutral-300"
                                            }`}
                                        >
                                            {endpoint.method}
                                        </span>
                                    </td>
                                    <td
                                        class="p-4 font-mono text-xs text-neutral-300"
                                        >{endpoint.path}</td
                                    >
                                    <td class="p-4 text-right font-bold"
                                        >{endpoint.hit_count}</td
                                    >
                                    <td
                                        class="p-4 text-right text-muted-foreground"
                                        >{endpoint.avg_latency_ms.toFixed(
                                            2,
                                        )}ms</td
                                    >
                                    <td
                                        class="p-4 text-right text-xs text-muted-foreground"
                                    >
                                        {new Date(
                                            endpoint.last_seen,
                                        ).toLocaleString()}
                                    </td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </CardContent>
        </Card>
    {/if}
</div>
