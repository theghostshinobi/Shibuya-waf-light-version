<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";

    let metrics = {
        avgDepth: 0,
        maxDepth: 10,
        avgComplexity: 0,
        maxComplexity: 1000,
        totalQueries: 0,
        blockedQueries: 0,
        introspectionBlocked: 0,
        batchOverflows: 0,
        depthViolations: 0,
        complexityViolations: 0,
    };
    let loading = true;
    let error = "";

    onMount(async () => {
        try {
            const data = await api.getGraphQLStats();
            metrics = {
                avgDepth: data.avg_depth ?? 0,
                maxDepth: data.max_depth ?? 10,
                avgComplexity: data.avg_complexity ?? 0,
                maxComplexity: data.max_complexity ?? 1000,
                totalQueries: data.total_queries ?? 0,
                blockedQueries: data.blocked_queries ?? 0,
                introspectionBlocked: data.introspection_blocked ?? 0,
                batchOverflows: data.batch_overflows ?? 0,
                depthViolations: data.depth_violations ?? 0,
                complexityViolations: data.complexity_violations ?? 0,
            };
        } catch (e: any) {
            error = e.message || "Failed to load GraphQL stats";
            console.error("GraphQL stats fetch error:", e);
        } finally {
            loading = false;
        }
    });
</script>

<div class="space-y-6 p-6">
    <h1 class="text-3xl font-bold text-white">GraphQL Protection</h1>

    {#if loading}
        <div class="text-gray-400">Loading GraphQL stats...</div>
    {:else if error}
        <div class="text-red-400 bg-red-900/20 border border-red-700 rounded-lg p-4">
            {error}
        </div>
    {:else}
        <!-- Metrics Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Avg Depth</div>
                <div class="text-2xl font-bold text-white">{metrics.avgDepth.toFixed(1)}</div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Max Depth (Limit: {metrics.maxDepth})</div>
                <div class="text-2xl font-bold text-yellow-400">{metrics.depthViolations}</div>
                <div class="text-xs text-gray-500 mt-1">violations</div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Avg Complexity</div>
                <div class="text-2xl font-bold text-white">{metrics.avgComplexity.toFixed(0)}</div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Max Complexity (Limit: {metrics.maxComplexity})</div>
                <div class="text-2xl font-bold text-green-400">{metrics.complexityViolations}</div>
                <div class="text-xs text-gray-500 mt-1">violations</div>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Total Queries</div>
                <div class="text-2xl font-bold text-blue-400">{metrics.totalQueries}</div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Blocked Queries</div>
                <div class="text-2xl font-bold text-red-400">{metrics.blockedQueries}</div>
            </div>
            <div class="bg-gray-800 p-4 rounded-lg border border-gray-700 text-center">
                <div class="text-gray-400 text-sm">Introspection Blocked</div>
                <div class="text-2xl font-bold text-orange-400">{metrics.introspectionBlocked}</div>
            </div>
        </div>

        <!-- Security Events Table -->
        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 class="text-xl font-bold text-purple-400 mb-4">GraphQL Security Summary</h2>
            <table class="w-full text-left">
                <thead>
                    <tr class="text-gray-400 border-b border-gray-700">
                        <th class="py-2">Category</th>
                        <th>Count</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr class="border-b border-gray-700/50 text-white">
                        <td class="py-3">Depth Violations</td>
                        <td>{metrics.depthViolations}</td>
                        <td>
                            <span class="px-2 py-1 text-xs rounded border {metrics.depthViolations > 0 ? 'bg-red-900/50 text-red-300 border-red-700' : 'bg-green-900/50 text-green-300 border-green-700'}">
                                {metrics.depthViolations > 0 ? 'Active' : 'Clear'}
                            </span>
                        </td>
                    </tr>
                    <tr class="border-b border-gray-700/50 text-white">
                        <td class="py-3">Complexity Violations</td>
                        <td>{metrics.complexityViolations}</td>
                        <td>
                            <span class="px-2 py-1 text-xs rounded border {metrics.complexityViolations > 0 ? 'bg-red-900/50 text-red-300 border-red-700' : 'bg-green-900/50 text-green-300 border-green-700'}">
                                {metrics.complexityViolations > 0 ? 'Active' : 'Clear'}
                            </span>
                        </td>
                    </tr>
                    <tr class="border-b border-gray-700/50 text-white">
                        <td class="py-3">Batch Overflows</td>
                        <td>{metrics.batchOverflows}</td>
                        <td>
                            <span class="px-2 py-1 text-xs rounded border {metrics.batchOverflows > 0 ? 'bg-red-900/50 text-red-300 border-red-700' : 'bg-green-900/50 text-green-300 border-green-700'}">
                                {metrics.batchOverflows > 0 ? 'Active' : 'Clear'}
                            </span>
                        </td>
                    </tr>
                    <tr class="border-b border-gray-700/50 text-white">
                        <td class="py-3">Introspection Blocked</td>
                        <td>{metrics.introspectionBlocked}</td>
                        <td>
                            <span class="px-2 py-1 text-xs rounded border bg-blue-900/50 text-blue-300 border-blue-700">
                                {metrics.introspectionBlocked > 0 ? 'Enforced' : 'Monitoring'}
                            </span>
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>
    {/if}
</div>
