<script>
    import { onMount } from "svelte";
    let specs = [
        {
            title: "Petstore API",
            basePath: "/api/v1",
            pathCount: 12,
            violations24h: 3,
        },
        {
            title: "Banking API",
            basePath: "/api/v2",
            pathCount: 45,
            violations24h: 12,
        },
    ];
    let violations = [
        {
            method: "GET",
            path: "/api/v1/users/abc",
            timestamp: "2026-01-26 10:30",
            errors: ['Path param "id": Not a valid integer'],
        },
        {
            method: "POST",
            path: "/api/v1/pets",
            timestamp: "2026-01-26 10:45",
            errors: ['Missing required field "name"'],
        },
    ];
</script>

<div class="space-y-6 p-6">
    <h1 class="text-3xl font-bold text-white">API Protection (OpenAPI)</h1>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 class="text-xl font-bold text-blue-400 mb-4">
                Active Specifications
            </h2>
            <div class="space-y-4">
                {#each specs as spec}
                    <div
                        class="flex justify-between items-center p-3 bg-gray-900 rounded border border-gray-600"
                    >
                        <div>
                            <div class="font-bold text-white">{spec.title}</div>
                            <div class="text-sm text-gray-400">
                                <code>{spec.basePath}</code> • {spec.pathCount} endpoints
                            </div>
                        </div>
                        <div class="text-right">
                            <div class="text-red-400 font-bold">
                                {spec.violations24h} violations
                            </div>
                            <div class="text-xs text-gray-500">Last 24h</div>
                        </div>
                    </div>
                {/each}
            </div>
        </div>

        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700">
            <h2 class="text-xl font-bold text-red-400 mb-4">
                Recent Violations
            </h2>
            <div class="space-y-4">
                {#each violations as v}
                    <div
                        class="p-3 bg-red-900/20 rounded border border-red-900/50"
                    >
                        <div
                            class="flex justify-between text-xs text-gray-400 mb-1"
                        >
                            <span>{v.method} {v.path}</span>
                            <span>{v.timestamp}</span>
                        </div>
                        <div class="text-sm text-red-300">
                            {#each v.errors as err}
                                <div>• {err}</div>
                            {/each}
                        </div>
                    </div>
                {/each}
            </div>
        </div>
    </div>
</div>
