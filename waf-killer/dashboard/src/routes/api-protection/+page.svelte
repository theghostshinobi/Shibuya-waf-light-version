<script lang="ts">
    import { onMount } from "svelte";
    import { writable } from "svelte/store";
    import api from "$lib/api/client";

    // State
    let openApiSpec = writable<string>(""); // YAML content
    let specLoaded = writable<boolean>(false);
    let config = {
        graphql_max_depth: 7,
        graphql_max_complexity: 1000,
        openapi_validation_enabled: true,
    };

    let stats = {
        total_validations: 0,
        blocked_by_openapi: 0,
        blocked_by_graphql_depth: 0,
        blocked_by_graphql_complexity: 0,
    };

    // Load initial data
    onMount(async () => {
        await loadConfig();
        await loadStats();
    });

    async function loadConfig() {
        try {
            const response = await api.getConfig();
            config = {
                graphql_max_depth: response.graphql_max_depth || 7,
                graphql_max_complexity: response.graphql_max_complexity || 1000,
                openapi_validation_enabled:
                    response.openapi_validation_enabled || false,
            };
        } catch (err) {
            console.error("Failed to load config:", err);
        }
    }

    async function loadStats() {
        try {
            const response = await api.getStats();
            stats = {
                total_validations: response.api_validations || 0,
                blocked_by_openapi: response.openapi_blocks || 0,
                blocked_by_graphql_depth: response.graphql_depth_blocks || 0,
                blocked_by_graphql_complexity:
                    response.graphql_complexity_blocks || 0,
            };
        } catch (err) {
            console.error("Failed to load stats:", err);
        }
    }

    async function uploadOpenApiSpec(event: Event) {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (e) => {
            const content = e.target?.result as string;
            openApiSpec.set(content);

            try {
                await api.uploadOpenApiSpec(content);
                specLoaded.set(true);
                alert("OpenAPI spec uploaded successfully!");
            } catch (err) {
                alert("Failed to upload spec: " + err);
            }
        };
        reader.readAsText(file);
    }

    async function saveConfig() {
        try {
            await api.updateConfig(config);
            alert("Configuration saved!");
        } catch (err) {
            alert("Failed to save config: " + err);
        }
    }
</script>

<div class="container mx-auto p-6 text-white">
    <h1 class="text-3xl font-bold mb-6">🛡️ API Protection</h1>

    <!-- Statistics Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div class="bg-[#111] border border-[#333] p-4 rounded-lg shadow">
            <div class="text-sm text-gray-500">Total Validations</div>
            <div class="text-2xl font-bold">{stats.total_validations}</div>
        </div>
        <div class="bg-[#111] border border-[#333] p-4 rounded-lg shadow">
            <div class="text-sm text-gray-500">OpenAPI Blocks</div>
            <div class="text-2xl font-bold text-red-500">
                {stats.blocked_by_openapi}
            </div>
        </div>
        <div class="bg-[#111] border border-[#333] p-4 rounded-lg shadow">
            <div class="text-sm text-gray-500">GraphQL Depth Blocks</div>
            <div class="text-2xl font-bold text-orange-500">
                {stats.blocked_by_graphql_depth}
            </div>
        </div>
        <div class="bg-[#111] border border-[#333] p-4 rounded-lg shadow">
            <div class="text-sm text-gray-500">GraphQL Complexity Blocks</div>
            <div class="text-2xl font-bold text-yellow-500">
                {stats.blocked_by_graphql_complexity}
            </div>
        </div>
    </div>

    <!-- OpenAPI Section -->
    <div class="bg-[#111] border border-[#333] p-6 rounded-lg shadow mb-6">
        <h2 class="text-xl font-bold mb-4">📄 OpenAPI Specification</h2>

        <div class="mb-4">
            <label class="flex items-center space-x-2 cursor-pointer">
                <input
                    type="checkbox"
                    bind:checked={config.openapi_validation_enabled}
                    class="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Enable OpenAPI Validation</span>
            </label>
        </div>

        <div class="mb-4">
            <label class="block text-sm font-medium mb-2"
                >Upload OpenAPI YAML</label
            >
            <input
                type="file"
                accept=".yaml,.yml"
                on:change={uploadOpenApiSpec}
                class="block w-full text-sm text-gray-400
          file:mr-4 file:py-2 file:px-4
          file:rounded-md file:border-0
          file:text-sm file:font-semibold
          file:bg-[#222] file:text-white
          hover:file:bg-[#333]
          cursor-pointer bg-[#000] border border-[#333] rounded-md p-1"
            />
        </div>

        {#if $specLoaded}
            <div
                class="bg-green-900/30 border border-green-500/50 text-green-400 p-3 rounded"
            >
                ✅ OpenAPI spec loaded and active
            </div>
        {:else}
            <div
                class="bg-yellow-900/30 border border-yellow-500/50 text-yellow-400 p-3 rounded"
            >
                ⚠️ No OpenAPI spec loaded. Upload one to enable schema
                validation.
            </div>
        {/if}
    </div>

    <!-- GraphQL Configuration -->
    <div class="bg-[#111] border border-[#333] p-6 rounded-lg shadow mb-6">
        <h2 class="text-xl font-bold mb-4">🔷 GraphQL Protection</h2>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
                <label class="block text-sm font-medium mb-2"
                    >Max Query Depth</label
                >
                <input
                    type="number"
                    bind:value={config.graphql_max_depth}
                    min="1"
                    max="20"
                    class="w-full bg-black border border-[#333] rounded p-2 text-white outline-none focus:border-blue-500"
                />
                <p class="text-xs text-gray-500 mt-1">
                    Blocks deeply nested queries (DoS protection)
                </p>
            </div>

            <div>
                <label class="block text-sm font-medium mb-2"
                    >Max Query Complexity</label
                >
                <input
                    type="number"
                    bind:value={config.graphql_max_complexity}
                    min="100"
                    max="10000"
                    step="100"
                    class="w-full bg-black border border-[#333] rounded p-2 text-white outline-none focus:border-blue-500"
                />
                <p class="text-xs text-gray-500 mt-1">
                    Blocks expensive queries (cost-based protection)
                </p>
            </div>
        </div>
    </div>

    <!-- Save Button -->
    <div class="flex justify-end">
        <button
            on:click={saveConfig}
            class="bg-blue-600 hover:bg-blue-700 text-white px-8 py-2.5 rounded-md font-medium transition-colors shadow-lg shadow-blue-900/20"
        >
            💾 Save Configuration
        </button>
    </div>
</div>
