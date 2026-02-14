<script lang="ts">
    import { api } from "$lib/api/client";
    import { onMount } from "svelte";
    import { fade, slide } from "svelte/transition";
    import type { WafConfig } from "$lib/types";
    import {
        Settings,
        Shield,
        Zap,
        Brain,
        Globe,
        Save,
        RotateCcw,
        CheckCircle,
        AlertTriangle,
        Loader2,
        Server,
        ShieldCheck,
        Lock,
    } from "lucide-svelte";

    let activeTab = "general";
    let isLoading = false;
    let showToast = false;
    let toastMessage = "";

    // Loading state for initial config fetch
    let isLoadingConfig = true;
    let loadError: string | null = null;

    // Full backend config for merging
    let fullBackendConfig: WafConfig | null = null;

    // Upstream Data
    let upstreamConfig = {
        backend_url: "",
        pool_size: 100,
        connect_timeout: 5, // seconds
        request_timeout: 30, // seconds
        health_check_path: "/health",
        health_check_interval: 10,
    };
    let upstreamValidation = {
        urlValid: true,
        urlError: "",
    };

    // Form Data (defaults used only as fallback if fetch fails)
    let config = {
        // Rate Limit
        burst_size: 50,
        requests_per_sec: 100,
        ban_duration: 3600,

        // ML
        ml_threshold: 0.7,
        ml_auto_block: false,

        // Network
        whitelist: "",
        blacklist: "",

        // General
        paranoia_level: 1,
        detection_mode: "Blocking",

        // API Protection
        api_enabled: true,
        graphql_max_depth: 7,
        graphql_max_complexity: 1000,
        graphql_introspection: false,

        // Security
        allowed_methods: "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH",
    };

    const tabs = [
        { id: "general", label: "General", icon: Settings },
        { id: "upstream", label: "Upstream", icon: Server },
        { id: "api_protection", label: "API Protection", icon: ShieldCheck },
        { id: "security", label: "Security", icon: Lock },
        { id: "ratelimit", label: "Rate Limit", icon: Zap },
        { id: "ml", label: "Advanced ML", icon: Brain },
        { id: "network", label: "Network", icon: Globe },
    ];

    // Helper: Parse "5s" -> 5
    function parseDuration(d: string | number | undefined): number {
        if (!d) return 0;
        if (typeof d === "number") return d;
        return parseInt(d.toString().replace("s", ""), 10) || 0;
    }

    // Helper: Validate URL
    function validateBackendUrl(url: string) {
        if (!url) {
            upstreamValidation.urlValid = false;
            upstreamValidation.urlError = "Backend URL is required";
            return;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            upstreamValidation.urlValid = false;
            upstreamValidation.urlError = "Must start with http:// or https://";
            return;
        }
        try {
            new URL(url);
            upstreamValidation.urlValid = true;
            upstreamValidation.urlError = "";
        } catch {
            upstreamValidation.urlValid = false;
            upstreamValidation.urlError = "Invalid URL format";
        }
    }

    // Helper to map backend detection mode to UI
    function mapDetectionMode(mode: string | undefined): string {
        if (!mode) return "Blocking";
        const modeMap: Record<string, string> = {
            off: "Off",
            detection: "Detection",
            blocking: "Blocking",
        };
        return modeMap[mode.toLowerCase()] || "Blocking";
    }

    // Fetch current config from backend
    async function loadConfig() {
        isLoadingConfig = true;
        loadError = null;
        try {
            const response = await api.getConfig();
            // Handle both shapes: { config: {...} } or direct config object
            const cfg = (response?.config ?? response) as WafConfig;
            if (!cfg || typeof cfg !== "object")
                throw new Error("Invalid config response");
            fullBackendConfig = cfg;

            // Map backend fields to form variables
            config.burst_size = cfg.detection?.rate_limiting?.burst_size ?? 50;
            config.requests_per_sec =
                cfg.detection?.rate_limiting?.requests_per_second ?? 100;
            config.ban_duration =
                cfg.detection?.rate_limiting?.ban_duration_secs ?? 3600;
            config.ml_threshold = cfg.ml?.threshold ?? 0.7;
            config.ml_auto_block = cfg.ml?.shadow_mode ?? false;
            config.paranoia_level = cfg.detection?.crs?.paranoia_level ?? 1;
            config.detection_mode = mapDetectionMode(cfg.detection?.mode);

            // Map Upstream fields
            if (cfg.upstream) {
                upstreamConfig.backend_url = cfg.upstream.backend_url ?? "";
                upstreamConfig.pool_size = cfg.upstream.pool_size ?? 100;
                upstreamConfig.connect_timeout = parseDuration(
                    cfg.upstream.connect_timeout,
                );
                upstreamConfig.request_timeout = parseDuration(
                    cfg.upstream.request_timeout,
                );
                upstreamConfig.health_check_path =
                    cfg.upstream.health_check?.path ?? "/health";
                upstreamConfig.health_check_interval = parseDuration(
                    cfg.upstream.health_check?.interval ?? 10,
                );

                validateBackendUrl(upstreamConfig.backend_url);
            }

            // Map Security fields
            config.whitelist = "";
            config.blacklist = (cfg.security?.blocked_user_agents ?? []).join(
                "\n",
            );
            config.allowed_methods = (
                cfg.security?.allowed_methods ?? [
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "OPTIONS",
                    "HEAD",
                    "PATCH",
                ]
            ).join(", ");

            // Map API Protection fields
            if (cfg.api_protection) {
                config.api_enabled = cfg.api_protection.enabled ?? true;
                config.graphql_max_depth =
                    cfg.api_protection.graphql?.max_depth ?? 7;
                config.graphql_max_complexity =
                    cfg.api_protection.graphql?.max_complexity ?? 1000;
                config.graphql_introspection =
                    cfg.api_protection.graphql?.introspection_enabled ?? false;
            }

            console.log("Config loaded successfully from backend");
        } catch (e) {
            loadError =
                e instanceof Error ? e.message : "Failed to load configuration";
            console.warn("Config load warning — using defaults:", e);
            // Don't block the UI. Defaults are already set above.
        } finally {
            isLoadingConfig = false;
        }
    }

    // Fetch config on component mount
    onMount(() => {
        loadConfig();
    });

    async function saveConfig() {
        if (!fullBackendConfig) {
            alert("Cannot save: Configuration not loaded.");
            return;
        }

        // Confirmation for backend URL change
        if (
            upstreamConfig.backend_url !==
            fullBackendConfig.upstream?.backend_url
        ) {
            if (
                !confirm(
                    "⚠️ You are changing the backend URL. All proxied traffic will be redirected immediately. Continue?",
                )
            ) {
                return;
            }
        }

        isLoading = true;
        try {
            // Construct NESTED payload by merging changes into full config
            const newConfig: WafConfig = JSON.parse(
                JSON.stringify(fullBackendConfig),
            );

            // Update Detection
            if (!newConfig.detection) newConfig.detection = {} as any;
            newConfig.detection.mode = config.detection_mode.toLowerCase();

            if (!newConfig.detection.rate_limiting)
                newConfig.detection.rate_limiting = {} as any;
            newConfig.detection.rate_limiting.burst_size = config.burst_size;
            newConfig.detection.rate_limiting.requests_per_second =
                config.requests_per_sec;
            newConfig.detection.rate_limiting.ban_duration_secs =
                config.ban_duration;

            if (!newConfig.detection.crs) newConfig.detection.crs = {} as any;
            newConfig.detection.crs.paranoia_level = config.paranoia_level;

            // Update ML
            if (!newConfig.ml) newConfig.ml = {} as any;
            newConfig.ml.threshold = config.ml_threshold;
            newConfig.ml.shadow_mode = config.ml_auto_block;

            // Update Security
            if (!newConfig.security) newConfig.security = {} as any;
            newConfig.security.blocked_user_agents = config.blacklist
                .split("\n")
                .map((x) => x.trim())
                .filter((x) => x.length > 0);

            newConfig.security.allowed_methods = config.allowed_methods
                .split(",")
                .map((x) => x.trim().toUpperCase())
                .filter((x) => x.length > 0);

            // Update API Protection
            if (!newConfig.api_protection)
                newConfig.api_protection = { graphql: {} } as any;
            newConfig.api_protection!.enabled = config.api_enabled;
            newConfig.api_protection!.graphql.max_depth =
                config.graphql_max_depth;
            newConfig.api_protection!.graphql.max_complexity =
                config.graphql_max_complexity;
            newConfig.api_protection!.graphql.introspection_enabled =
                config.graphql_introspection;
            newConfig.api_protection!.graphql.max_batch_size = 5; // Default

            // Update Upstream
            if (!newConfig.upstream) newConfig.upstream = {} as any;
            newConfig.upstream.backend_url = upstreamConfig.backend_url;
            newConfig.upstream.pool_size = upstreamConfig.pool_size;
            newConfig.upstream.connect_timeout = `${upstreamConfig.connect_timeout}s`;
            newConfig.upstream.request_timeout = `${upstreamConfig.request_timeout}s`;

            // Health Check
            if (!newConfig.upstream.health_check)
                newConfig.upstream.health_check = {} as any;
            newConfig.upstream.health_check.path =
                upstreamConfig.health_check_path;
            newConfig.upstream.health_check.interval = `${upstreamConfig.health_check_interval}s`;
            newConfig.upstream.health_check.enabled = true; // Implicitly enable if configured

            const res = await api.updateConfig(newConfig);
            if (res.success) {
                showToast = true;
                toastMessage = "Configuration saved successfully.";
                setTimeout(() => (showToast = false), 3000);
                await loadConfig();
            }
        } catch (e) {
            console.error(e);
            alert("Failed to update config");
        } finally {
            isLoading = false;
        }
    }
</script>

<div class="h-full flex flex-col p-6 space-y-6 max-w-5xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold tracking-tight">
                System Configuration
            </h1>
            <p class="text-gray-400 mt-1 text-sm">
                Fine-tune Shibuya"s inspection engine and sensitivity
                parameters.
            </p>
        </div>

        <div class="flex gap-3">
            <button
                disabled={isLoadingConfig}
                class="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors border border-[#333] rounded-md hover:bg-[#111] flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
                <RotateCcw size={14} />
                Reset Defaults
            </button>
            <button
                on:click={saveConfig}
                disabled={isLoading ||
                    isLoadingConfig ||
                    loadError !== null ||
                    !upstreamValidation.urlValid}
                class="px-4 py-2 text-sm bg-white text-black font-medium rounded-md hover:bg-gray-200 transition-colors flex items-center gap-2 shadow-[0_0_15px_rgba(255,255,255,0.1)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
                {#if isLoading}
                    <div
                        class="w-4 h-4 border-2 border-black/30 border-t-black rounded-full animate-spin"
                    ></div>
                {:else}
                    <Save size={14} />
                {/if}
                Apply Changes
            </button>
        </div>
    </div>

    <!-- Tabs -->
    <div class="border-b border-[#333] flex gap-6">
        {#each tabs as tab}
            <button
                on:click={() => (activeTab = tab.id)}
                class="pb-3 text-sm font-medium transition-all flex items-center gap-2 relative {activeTab ===
                tab.id
                    ? 'text-white'
                    : 'text-gray-500 hover:text-gray-300'}"
            >
                <svelte:component this={tab.icon} size={16} />
                {tab.label}
                {#if activeTab === tab.id}
                    <div
                        class="absolute bottom-0 left-0 w-full h-[1px] bg-white transition-all"
                    ></div>
                {/if}
            </button>
        {/each}
    </div>

    <!-- Content -->
    <div
        class="flex-1 bg-[#0A0A0A] border border-[#222] rounded-lg p-6 relative overflow-hidden"
    >
        {#if isLoadingConfig}
            <!-- Loading State -->
            <div
                class="flex flex-col items-center justify-center h-64"
                in:fade={{ duration: 200 }}
            >
                <Loader2 size={32} class="text-white animate-spin mb-4" />
                <p class="text-gray-400 text-sm">Loading configuration...</p>
            </div>
        {:else}
            <!-- Warning banner when backend is unavailable (non-blocking) -->
            {#if loadError}
                <div
                    class="bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-3 mb-4 flex items-center justify-between"
                    in:fade={{ duration: 200 }}
                >
                    <div class="flex items-center gap-3">
                        <AlertTriangle
                            size={18}
                            class="text-amber-400 flex-shrink-0"
                        />
                        <div>
                            <span class="text-amber-300 text-sm font-medium"
                                >Backend offline</span
                            >
                            <span class="text-gray-400 text-sm">
                                — showing defaults. Connect the backend to load
                                live config.</span
                            >
                        </div>
                    </div>
                    <button
                        on:click={loadConfig}
                        class="px-3 py-1 text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded-md hover:bg-amber-500/30 transition-colors flex-shrink-0"
                    >
                        Retry
                    </button>
                </div>
            {/if}

            {#if activeTab === "upstream"}
                <div in:fade={{ duration: 200 }} class="space-y-8 max-w-xl">
                    <div class="space-y-4">
                        <label class="block text-sm font-medium text-gray-300"
                            >Backend URL</label
                        >
                        <div class="relative">
                            <input
                                type="text"
                                bind:value={upstreamConfig.backend_url}
                                on:input={() =>
                                    validateBackendUrl(
                                        upstreamConfig.backend_url,
                                    )}
                                disabled={isLoadingConfig}
                                class="w-full bg-[#111] border {upstreamValidation.urlValid
                                    ? 'border-[#333] focus:border-white'
                                    : 'border-red-500/50 focus:border-red-500'} rounded-md px-3 py-2 text-white focus:outline-none transition-colors"
                                placeholder="http://localhost:3000"
                            />
                            {#if !upstreamValidation.urlValid}
                                <p class="text-red-400 text-xs mt-1">
                                    {upstreamValidation.urlError}
                                </p>
                            {/if}
                        </div>
                    </div>

                    <div class="grid grid-cols-2 gap-6">
                        <div class="space-y-2">
                            <label
                                class="block text-sm font-medium text-gray-300"
                                >Connect Timeout (sec)</label
                            >
                            <input
                                type="number"
                                min="1"
                                max="60"
                                disabled={isLoadingConfig}
                                bind:value={upstreamConfig.connect_timeout}
                                class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                        </div>
                        <div class="space-y-2">
                            <label
                                class="block text-sm font-medium text-gray-300"
                                >Request Timeout (sec)</label
                            >
                            <input
                                type="number"
                                min="1"
                                max="300"
                                disabled={isLoadingConfig}
                                bind:value={upstreamConfig.request_timeout}
                                class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                        </div>
                    </div>

                    <!-- Health Check -->
                    <div class="space-y-4 pt-4 border-t border-[#222]">
                        <h3
                            class="text-sm font-medium text-white flex items-center gap-2"
                        >
                            <span class="w-2 h-2 rounded-full bg-blue-500"
                            ></span> Health Check
                        </h3>
                        <div class="grid grid-cols-2 gap-6">
                            <div class="space-y-2">
                                <label
                                    class="block text-sm font-medium text-gray-300"
                                    >Path</label
                                >
                                <input
                                    type="text"
                                    bind:value={
                                        upstreamConfig.health_check_path
                                    }
                                    class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                                    placeholder="/health"
                                />
                            </div>
                            <div class="space-y-2">
                                <label
                                    class="block text-sm font-medium text-gray-300"
                                    >Interval (sec)</label
                                >
                                <input
                                    type="number"
                                    min="1"
                                    max="60"
                                    bind:value={
                                        upstreamConfig.health_check_interval
                                    }
                                    class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                                />
                            </div>
                        </div>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300"
                            >Connection Pool Size</label
                        >
                        <div class="flex gap-2">
                            <input
                                type="number"
                                min="1"
                                max="1000"
                                disabled={isLoadingConfig}
                                bind:value={upstreamConfig.pool_size}
                                class="flex-1 bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                        </div>
                    </div>
                </div>
            {:else if activeTab === "api_protection"}
                <div in:fade={{ duration: 200 }} class="space-y-8 max-w-xl">
                    <div
                        class="flex items-center justify-between p-4 bg-[#111] border border-[#222] rounded-lg"
                    >
                        <div>
                            <h3 class="text-sm font-medium text-white">
                                API Protection Enabled
                            </h3>
                            <p class="text-xs text-gray-500 mt-1">
                                Enforces schema validation and limits for
                                GraphQL/OpenAPI.
                            </p>
                        </div>
                        <button
                            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none {config.api_enabled
                                ? 'bg-emerald-600'
                                : 'bg-[#333]'}"
                            on:click={() =>
                                (config.api_enabled = !config.api_enabled)}
                        >
                            <span
                                class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform {config.api_enabled
                                    ? 'translate-x-6'
                                    : 'translate-x-1'}"
                            />
                        </button>
                    </div>

                    {#if config.api_enabled}
                        <div class="space-y-6" transition:slide>
                            <h3
                                class="text-sm font-medium text-purple-400 uppercase tracking-wider"
                            >
                                GraphQL Limits
                            </h3>

                            <div class="space-y-4">
                                <div class="flex justify-between">
                                    <label class="text-sm text-gray-300"
                                        >Max Query Depth</label
                                    >
                                    <span class="text-sm font-mono text-white"
                                        >{config.graphql_max_depth}</span
                                    >
                                </div>
                                <input
                                    type="range"
                                    min="1"
                                    max="15"
                                    step="1"
                                    bind:value={config.graphql_max_depth}
                                    class="w-full h-2 bg-[#222] rounded-lg appearance-none cursor-pointer accent-purple-500"
                                />
                            </div>

                            <div class="space-y-4">
                                <div class="flex justify-between">
                                    <label class="text-sm text-gray-300"
                                        >Max Complexity</label
                                    >
                                    <span class="text-sm font-mono text-white"
                                        >{config.graphql_max_complexity}</span
                                    >
                                </div>
                                <input
                                    type="range"
                                    min="100"
                                    max="5000"
                                    step="100"
                                    bind:value={config.graphql_max_complexity}
                                    class="w-full h-2 bg-[#222] rounded-lg appearance-none cursor-pointer accent-purple-500"
                                />
                            </div>

                            <div class="flex items-center justify-between">
                                <label class="text-sm text-gray-300"
                                    >Allow Introspection</label
                                >
                                <button
                                    class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none {config.graphql_introspection
                                        ? 'bg-purple-600'
                                        : 'bg-[#333]'}"
                                    on:click={() =>
                                        (config.graphql_introspection =
                                            !config.graphql_introspection)}
                                >
                                    <span
                                        class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform {config.graphql_introspection
                                            ? 'translate-x-6'
                                            : 'translate-x-1'}"
                                    />
                                </button>
                            </div>
                        </div>
                    {/if}
                </div>
            {:else if activeTab === "security"}
                <div in:fade={{ duration: 200 }} class="space-y-8 max-w-xl">
                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300"
                            >Allowed HTTP Methods</label
                        >
                        <input
                            type="text"
                            bind:value={config.allowed_methods}
                            class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            placeholder="GET, POST, PUT, DELETE"
                        />
                        <p class="text-xs text-gray-500">
                            Comma-separated list of allowed verbs. Others will
                            be blocked.
                        </p>
                    </div>

                    <div class="space-y-2">
                        <label
                            class="block text-sm font-medium text-gray-300 flex items-center gap-2"
                        >
                            <span class="w-2 h-2 rounded-full bg-red-500"
                            ></span> Blocked User Agents
                        </label>
                        <textarea
                            bind:value={config.blacklist}
                            class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-sm font-mono text-gray-300 focus:outline-none focus:border-red-500/50 resize-none h-40"
                            placeholder="BadBot/1.0&#10;Scraper"
                        ></textarea>
                    </div>
                </div>
            {:else if activeTab === "general"}
                <div in:fade={{ duration: 200 }} class="space-y-6 max-w-xl">
                    <div class="space-y-4">
                        <label class="block text-sm font-medium text-gray-300"
                            >Detection Mode</label
                        >
                        <div class="grid grid-cols-3 gap-3">
                            {#each ["Detection", "Blocking", "Off"] as mode}
                                <button
                                    class="px-4 py-3 rounded-md border text-sm font-medium transition-all {config.detection_mode ===
                                    mode
                                        ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400'
                                        : 'border-[#333] bg-[#111] text-gray-400 hover:border-gray-600'}"
                                    on:click={() =>
                                        (config.detection_mode = mode)}
                                >
                                    {mode}
                                </button>
                            {/each}
                        </div>
                        <p class="text-xs text-gray-500">
                            "Blocking" will actively drop requests. "Detection"
                            logs only.
                        </p>
                    </div>

                    <div class="space-y-4 pt-4 border-t border-[#222]">
                        <label class="block text-sm font-medium text-gray-300"
                            >Paranoia Level (PL)</label
                        >
                        <input
                            type="range"
                            min="1"
                            max="4"
                            step="1"
                            bind:value={config.paranoia_level}
                            class="w-full h-2 bg-[#222] rounded-lg appearance-none cursor-pointer accent-white"
                        />
                        <div
                            class="flex justify-between text-xs text-gray-500 font-mono"
                        >
                            <span>PL1 (Fast)</span>
                            <span>PL2</span>
                            <span>PL3</span>
                            <span>PL4 (Strict)</span>
                        </div>
                        <div
                            class="text-xs text-gray-400 bg-[#111] p-3 rounded border border-[#222]"
                        >
                            Current: <span class="text-white font-bold"
                                >PL{config.paranoia_level}</span
                            >.
                            {#if config.paranoia_level >= 3}
                                <span class="text-amber-500"
                                    >Warning: High risk of false positives.</span
                                >
                            {:else}
                                Standard baseline protection.
                            {/if}
                        </div>
                    </div>
                </div>
            {/if}

            {#if activeTab === "ratelimit"}
                <div in:fade={{ duration: 200 }} class="space-y-8 max-w-xl">
                    <div class="grid grid-cols-2 gap-6">
                        <div class="space-y-2">
                            <label
                                class="block text-sm font-medium text-gray-300"
                                >Burst Size</label
                            >
                            <input
                                type="number"
                                bind:value={config.burst_size}
                                class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                        </div>
                        <div class="space-y-2">
                            <label
                                class="block text-sm font-medium text-gray-300"
                                >Requests / Sec</label
                            >
                            <input
                                type="number"
                                bind:value={config.requests_per_sec}
                                class="w-full bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                        </div>
                    </div>

                    <div class="space-y-2">
                        <label class="block text-sm font-medium text-gray-300"
                            >Ban Duration (Seconds)</label
                        >
                        <div class="flex gap-2">
                            <input
                                type="number"
                                bind:value={config.ban_duration}
                                class="flex-1 bg-[#111] border border-[#333] rounded-md px-3 py-2 text-white focus:outline-none focus:border-white transition-colors"
                            />
                            <span
                                class="inline-flex items-center px-3 text-sm text-gray-500 bg-[#151515] border border-[#333] rounded-md"
                            >
                                {(config.ban_duration / 60).toFixed(1)} mins
                            </span>
                        </div>
                    </div>
                </div>
            {/if}

            {#if activeTab === "ml"}
                <div in:fade={{ duration: 200 }} class="space-y-8 max-w-xl">
                    <div class="space-y-4">
                        <div class="flex justify-between">
                            <label
                                class="block text-sm font-medium text-gray-300"
                                >Anomaly Threshold</label
                            >
                            <span class="text-sm font-mono text-emerald-400"
                                >{config.ml_threshold}</span
                            >
                        </div>
                        <input
                            type="range"
                            min="0.1"
                            max="1.0"
                            step="0.05"
                            bind:value={config.ml_threshold}
                            class="w-full h-2 bg-[#222] rounded-lg appearance-none cursor-pointer accent-emerald-500"
                        />
                        <p class="text-xs text-gray-500">
                            Lower values make the ML engine more sensitive (more
                            blocks).
                        </p>
                    </div>

                    <div
                        class="flex items-center justify-between p-4 bg-[#111] border border-[#222] rounded-lg"
                    >
                        <div>
                            <h3 class="text-sm font-medium text-white">
                                Auto-Block Mode
                            </h3>
                            <p class="text-xs text-gray-500 mt-1">
                                Automatically ban IPs with high anomaly scores.
                            </p>
                        </div>
                        <button
                            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none {config.ml_auto_block
                                ? 'bg-emerald-600'
                                : 'bg-[#333]'}"
                            on:click={() =>
                                (config.ml_auto_block = !config.ml_auto_block)}
                        >
                            <span
                                class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform {config.ml_auto_block
                                    ? 'translate-x-6'
                                    : 'translate-x-1'}"
                            />
                        </button>
                    </div>
                </div>
            {/if}

            {#if activeTab === "network"}
                <div
                    in:fade={{ duration: 200 }}
                    class="grid grid-cols-2 gap-8 h-full"
                >
                    <div class="flex flex-col gap-2 h-full">
                        <label
                            class="block text-sm font-medium text-gray-300 flex items-center gap-2"
                        >
                            <span class="w-2 h-2 rounded-full bg-emerald-500"
                            ></span>
                            Whitelist (Trusted IPs)
                        </label>
                        <textarea
                            bind:value={config.whitelist}
                            class="flex-1 w-full bg-[#111] border border-[#333] rounded-md p-3 text-sm font-mono text-gray-300 focus:outline-none focus:border-emerald-500/50 resize-none"
                            placeholder="192.168.1.1&#10;10.0.0.0/24"
                        ></textarea>
                    </div>
                </div>
            {/if}
        {/if}
    </div>
</div>

<!-- Toast Notification -->
{#if showToast}
    <div
        transition:slide
        class="fixed bottom-6 right-6 bg-[#111] border border-[#333] text-white px-4 py-3 rounded-md shadow-2xl flex items-center gap-3 z-50"
    >
        <CheckCircle size={18} class="text-emerald-500" />
        <span class="text-sm font-medium">{toastMessage}</span>
    </div>
{/if}

<style>
    /* Custom scrollbar for textareas */
    textarea::-webkit-scrollbar {
        width: 8px;
    }
    textarea::-webkit-scrollbar-track {
        background: #0a0a0a;
    }
    textarea::-webkit-scrollbar-thumb {
        background: #222;
        border-radius: 4px;
    }
    textarea::-webkit-scrollbar-thumb:hover {
        background: #333;
    }
</style>
