<script lang="ts">
    import { fade, fly, scale } from "svelte/transition";
    import {
        Rocket,
        Shield,
        ArrowLeft,
        CheckCircle,
        AlertTriangle,
        Loader2,
        Copy,
        ExternalLink,
        Zap,
        Lock,
        Eye,
        Server,
        Globe,
        RefreshCw,
    } from "lucide-svelte";
    import api from "$lib/api/client";

    // ═══════════════════════════════════════════════
    // Types
    // ═══════════════════════════════════════════════

    type SetupState = "idle" | "testing" | "activating" | "active" | "error";
    type SecurityLevel = "strict" | "moderate" | "permissive";

    interface FrameworkPreset {
        name: string;
        url: string;
        level: SecurityLevel;
        color: string;
    }

    interface QuickSetupResponse {
        status: string;
        waf_url: string;
        backend_url: string;
        security_level: string;
        anomaly_threshold: number;
        rules_enabled: boolean;
        ml_enabled: boolean;
    }

    // ═══════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════

    let state: SetupState = "idle";
    let backendUrl = "";
    let securityLevel: SecurityLevel = "moderate";
    let errorMessage = "";
    let errorTips: string[] = [];
    let result: QuickSetupResponse | null = null;
    let copiedField: string | null = null;
    let urlTouched = false;

    // ═══════════════════════════════════════════════
    // Framework Presets
    // ═══════════════════════════════════════════════

    const presets: FrameworkPreset[] = [
        {
            name: "Next.js",
            url: "http://localhost:3000",
            level: "moderate",
            color: "#000",
        },
        {
            name: "Vite/React",
            url: "http://localhost:5173",
            level: "moderate",
            color: "#646cff",
        },
        {
            name: "Django",
            url: "http://localhost:8000",
            level: "strict",
            color: "#092e20",
        },
        {
            name: "Flask",
            url: "http://localhost:5000",
            level: "moderate",
            color: "#000",
        },
        {
            name: "Express",
            url: "http://localhost:3000",
            level: "moderate",
            color: "#68a063",
        },
        {
            name: "Laravel",
            url: "http://localhost:8000",
            level: "moderate",
            color: "#ff2d20",
        },
        {
            name: "Rails",
            url: "http://localhost:3000",
            level: "moderate",
            color: "#cc0000",
        },
        {
            name: "Go",
            url: "http://localhost:8080",
            level: "strict",
            color: "#00add8",
        },
    ];

    // ═══════════════════════════════════════════════
    // Security Level Details
    // ═══════════════════════════════════════════════

    const levelDetails: Record<
        SecurityLevel,
        { label: string; desc: string; threshold: number; icon: typeof Shield }
    > = {
        strict: {
            label: "Strict",
            desc: "Maximum protection. Blocks aggressively — may flag some legitimate edge-case requests.",
            threshold: 3,
            icon: Lock,
        },
        moderate: {
            label: "Moderate",
            desc: "Balanced protection. Blocks real attacks while keeping false positives low. Recommended.",
            threshold: 5,
            icon: Shield,
        },
        permissive: {
            label: "Permissive",
            desc: "Minimal friction. Only blocks obvious, high-confidence attacks.",
            threshold: 10,
            icon: Eye,
        },
    };

    // ═══════════════════════════════════════════════
    // URL Validation
    // ═══════════════════════════════════════════════

    function validateUrl(url: string): { valid: boolean; error: string } {
        if (!url.trim()) return { valid: false, error: "URL is required" };
        if (!/^https?:\/\//i.test(url))
            return {
                valid: false,
                error: "Must start with http:// or https://",
            };
        try {
            const parsed = new URL(url);
            if (!parsed.hostname)
                return { valid: false, error: "Missing hostname" };
            // Block SSRF to cloud metadata
            if (parsed.hostname === "169.254.169.254")
                return {
                    valid: false,
                    error: "Cloud metadata endpoints are blocked",
                };
            const port = parseInt(
                parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
            );
            if (port < 1 || port > 65535)
                return { valid: false, error: "Port must be 1–65535" };
            return { valid: true, error: "" };
        } catch {
            return { valid: false, error: "Invalid URL format" };
        }
    }

    $: urlValidation = validateUrl(backendUrl);
    $: canActivate = urlValidation.valid && state === "idle";

    // ═══════════════════════════════════════════════
    // Actions
    // ═══════════════════════════════════════════════

    function applyPreset(preset: FrameworkPreset) {
        backendUrl = preset.url;
        securityLevel = preset.level;
        urlTouched = true;
    }

    async function activate() {
        if (!urlValidation.valid) return;

        state = "testing";
        errorMessage = "";
        errorTips = [];

        // Minimum visible delay so users see the testing step
        await new Promise((r) => setTimeout(r, 800));

        state = "activating";

        try {
            const response: QuickSetupResponse = await api.quickSetup({
                backend_url: backendUrl,
                security_level: securityLevel,
            });

            result = response;
            state = "active";
        } catch (e: any) {
            state = "error";
            const msg = e?.message || "Unknown error";

            // Parse structured error if available
            if (
                msg.includes("Cannot connect") ||
                msg.includes("ECONNREFUSED") ||
                msg.includes("unreachable")
            ) {
                errorMessage = `Cannot reach ${backendUrl}. Is your app running?`;
                errorTips = [
                    `Check if your app is running: curl ${backendUrl}`,
                    "Verify the port number is correct",
                    "If using Docker, try http://host.docker.internal:PORT",
                ];
            } else if (msg.includes("Invalid") || msg.includes("format")) {
                errorMessage = "Invalid URL format. Use http://hostname:port";
                errorTips = [
                    "Include the protocol: http:// or https://",
                    "Example: http://localhost:3000",
                ];
            } else {
                errorMessage = msg;
                errorTips = [
                    "Check that the WAF backend is running",
                    "Try again in a few seconds",
                ];
            }
        }
    }

    function reset() {
        state = "idle";
        errorMessage = "";
        errorTips = [];
        result = null;
    }

    async function copyToClipboard(text: string, field: string) {
        try {
            await navigator.clipboard.writeText(text);
            copiedField = field;
            setTimeout(() => (copiedField = null), 2000);
        } catch {
            // Fallback
        }
    }
</script>

<svelte:head>
    <title>Quick Setup — SHIBUYA WAF</title>
</svelte:head>

<div class="min-h-full bg-black p-6 md:p-8">
    <div class="max-w-2xl mx-auto">
        <!-- Back Link -->
        <a
            href="/"
            class="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-white transition-colors mb-8"
        >
            <ArrowLeft size={14} />
            Back to Dashboard
        </a>

        <!-- ═══════════════════════════════════════ -->
        <!--  SUCCESS STATE                         -->
        <!-- ═══════════════════════════════════════ -->
        {#if state === "active" && result}
            <div in:fly={{ y: 20, duration: 400 }} class="space-y-6">
                <!-- Success Header -->
                <div class="text-center space-y-4">
                    <div
                        class="inline-flex items-center justify-center w-20 h-20 rounded-full bg-emerald-500/10 border border-emerald-500/30"
                    >
                        <CheckCircle size={40} class="text-emerald-400" />
                    </div>
                    <div>
                        <h1 class="text-3xl font-bold text-white">
                            Protection Active
                        </h1>
                        <p class="text-gray-400 mt-1">
                            Your website is now protected by SHIBUYA WAF
                        </p>
                    </div>
                </div>

                <!-- Info Cards -->
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div
                        class="bg-[#0a0a0a] border border-[#222] rounded-lg p-4 space-y-1"
                    >
                        <span
                            class="text-[11px] uppercase tracking-wider text-gray-500 font-medium"
                            >Protected URL</span
                        >
                        <div class="flex items-center gap-2">
                            <code
                                class="text-emerald-400 text-sm font-mono flex-1 truncate"
                                >{result.waf_url}</code
                            >
                            <button
                                on:click={() =>
                                    copyToClipboard(
                                        result?.waf_url ?? "",
                                        "waf",
                                    )}
                                class="p-1 text-gray-500 hover:text-white transition-colors"
                            >
                                {#if copiedField === "waf"}<CheckCircle
                                        size={14}
                                        class="text-emerald-400"
                                    />{:else}<Copy size={14} />{/if}
                            </button>
                        </div>
                    </div>
                    <div
                        class="bg-[#0a0a0a] border border-[#222] rounded-lg p-4 space-y-1"
                    >
                        <span
                            class="text-[11px] uppercase tracking-wider text-gray-500 font-medium"
                            >Backend</span
                        >
                        <div class="flex items-center gap-2">
                            <code
                                class="text-white text-sm font-mono flex-1 truncate"
                                >{result.backend_url}</code
                            >
                            <button
                                on:click={() =>
                                    copyToClipboard(
                                        result?.backend_url ?? "",
                                        "backend",
                                    )}
                                class="p-1 text-gray-500 hover:text-white transition-colors"
                            >
                                {#if copiedField === "backend"}<CheckCircle
                                        size={14}
                                        class="text-emerald-400"
                                    />{:else}<Copy size={14} />{/if}
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Security Badge -->
                <div
                    class="bg-[#0a0a0a] border border-[#222] rounded-lg p-4 flex items-center justify-between"
                >
                    <div class="flex items-center gap-3">
                        <Shield size={18} class="text-emerald-400" />
                        <div>
                            <span
                                class="text-sm text-white font-medium capitalize"
                                >{result.security_level}</span
                            >
                            <span class="text-gray-500 text-sm">
                                · Anomaly Threshold {result.anomaly_threshold}</span
                            >
                        </div>
                    </div>
                    <div class="flex items-center gap-2 text-xs">
                        {#if result.rules_enabled}<span
                                class="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 rounded-full border border-emerald-500/20"
                                >CRS Rules</span
                            >{/if}
                        {#if result.ml_enabled}<span
                                class="px-2 py-0.5 bg-blue-500/10 text-blue-400 rounded-full border border-blue-500/20"
                                >ML Engine</span
                            >{/if}
                    </div>
                </div>

                <!-- Test Commands -->
                <div
                    class="bg-[#0a0a0a] border border-[#222] rounded-lg p-5 space-y-4"
                >
                    <h3
                        class="text-sm font-medium text-white flex items-center gap-2"
                    >
                        <Zap size={14} class="text-amber-400" /> Test It Now
                    </h3>

                    <div class="space-y-3">
                        <div>
                            <p class="text-xs text-gray-500 mb-1">
                                Normal request (should pass ✅)
                            </p>
                            <div
                                class="flex items-center gap-2 bg-black rounded-md border border-[#333] px-3 py-2"
                            >
                                <code
                                    class="text-emerald-400 text-xs font-mono flex-1"
                                    >curl {result.waf_url}/ -k</code
                                >
                                <button
                                    on:click={() =>
                                        copyToClipboard(
                                            `curl ${result?.waf_url}/ -k`,
                                            "curl1",
                                        )}
                                    class="p-1 text-gray-500 hover:text-white transition-colors flex-shrink-0"
                                >
                                    {#if copiedField === "curl1"}<CheckCircle
                                            size={12}
                                            class="text-emerald-400"
                                        />{:else}<Copy size={12} />{/if}
                                </button>
                            </div>
                        </div>
                        <div>
                            <p class="text-xs text-gray-500 mb-1">
                                SQLi attack (should block 🛑)
                            </p>
                            <div
                                class="flex items-center gap-2 bg-black rounded-md border border-[#333] px-3 py-2"
                            >
                                <code
                                    class="text-red-400 text-xs font-mono flex-1 break-all"
                                    >curl "{result.waf_url}/?id=1' OR '1'='1" -k</code
                                >
                                <button
                                    on:click={() =>
                                        copyToClipboard(
                                            `curl "${result?.waf_url}/?id=1' OR '1'='1" -k`,
                                            "curl2",
                                        )}
                                    class="p-1 text-gray-500 hover:text-white transition-colors flex-shrink-0"
                                >
                                    {#if copiedField === "curl2"}<CheckCircle
                                            size={12}
                                            class="text-emerald-400"
                                        />{:else}<Copy size={12} />{/if}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Action Buttons -->
                <div class="flex gap-3">
                    <a
                        href="/"
                        class="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-white text-black font-medium rounded-lg hover:bg-gray-200 transition-colors text-sm"
                    >
                        <ExternalLink size={14} /> View Dashboard
                    </a>
                    <a
                        href="/settings"
                        class="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-[#111] text-white border border-[#333] font-medium rounded-lg hover:bg-[#1a1a1a] transition-colors text-sm"
                    >
                        Fine-tune Settings
                    </a>
                </div>

                <button
                    on:click={reset}
                    class="w-full text-center text-sm text-gray-500 hover:text-white transition-colors py-2"
                >
                    Set up a different backend →
                </button>
            </div>

            <!-- ═══════════════════════════════════════ -->
            <!--  ERROR STATE                           -->
            <!-- ═══════════════════════════════════════ -->
        {:else if state === "error"}
            <div in:fly={{ y: 20, duration: 400 }} class="space-y-6">
                <div class="text-center space-y-4">
                    <div
                        class="inline-flex items-center justify-center w-20 h-20 rounded-full bg-red-500/10 border border-red-500/30"
                    >
                        <AlertTriangle size={36} class="text-red-400" />
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold text-white">
                            Setup Failed
                        </h1>
                        <p class="text-gray-400 mt-2 max-w-md mx-auto">
                            {errorMessage}
                        </p>
                    </div>
                </div>

                {#if errorTips.length > 0}
                    <div
                        class="bg-[#0a0a0a] border border-[#222] rounded-lg p-5 space-y-3"
                    >
                        <h3 class="text-sm font-medium text-white">
                            Troubleshooting
                        </h3>
                        <ul class="space-y-2">
                            {#each errorTips as tip}
                                <li
                                    class="flex items-start gap-2 text-sm text-gray-400"
                                >
                                    <span class="text-gray-600 mt-0.5">→</span>
                                    <code
                                        class="text-xs bg-[#111] px-1.5 py-0.5 rounded font-mono"
                                        >{tip}</code
                                    >
                                </li>
                            {/each}
                        </ul>
                    </div>
                {/if}

                <div class="flex gap-3">
                    <button
                        on:click={reset}
                        class="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-white text-black font-medium rounded-lg hover:bg-gray-200 transition-colors text-sm"
                    >
                        <RefreshCw size={14} /> Try Again
                    </button>
                    <a
                        href="/settings"
                        class="flex-1 flex items-center justify-center gap-2 px-4 py-3 bg-[#111] text-white border border-[#333] font-medium rounded-lg hover:bg-[#1a1a1a] transition-colors text-sm"
                    >
                        Manual Config
                    </a>
                </div>
            </div>

            <!-- ═══════════════════════════════════════ -->
            <!--  LOADING STATES (testing / activating) -->
            <!-- ═══════════════════════════════════════ -->
        {:else if state === "testing" || state === "activating"}
            <div
                in:fade={{ duration: 200 }}
                class="flex flex-col items-center justify-center py-24 space-y-6"
            >
                <div class="relative">
                    <div
                        class="w-20 h-20 rounded-full bg-white/5 border border-[#333] flex items-center justify-center"
                    >
                        <Loader2 size={32} class="text-white animate-spin" />
                    </div>
                    <!-- Pulsing ring -->
                    <div
                        class="absolute inset-0 rounded-full border-2 border-white/10 animate-ping"
                    ></div>
                </div>
                <div class="text-center space-y-1">
                    {#if state === "testing"}
                        <p class="text-white font-medium">
                            Testing connectivity…
                        </p>
                        <p class="text-sm text-gray-500 font-mono">
                            {backendUrl}
                        </p>
                    {:else}
                        <p class="text-white font-medium">
                            Activating WAF protection…
                        </p>
                        <p class="text-sm text-gray-500">
                            Configuring proxy, rules, and ML engine
                        </p>
                    {/if}
                </div>
            </div>

            <!-- ═══════════════════════════════════════ -->
            <!--  IDLE — Main Setup Form                -->
            <!-- ═══════════════════════════════════════ -->
        {:else}
            <div in:fly={{ y: 20, duration: 400 }} class="space-y-8">
                <!-- Header -->
                <div class="space-y-2">
                    <div class="flex items-center gap-3">
                        <div
                            class="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center"
                        >
                            <Rocket size={20} class="text-white" />
                        </div>
                        <div>
                            <h1 class="text-2xl font-bold text-white">
                                Quick Setup
                            </h1>
                            <p class="text-gray-500 text-sm">
                                Protect your website in 30 seconds
                            </p>
                        </div>
                    </div>
                </div>

                <!-- Step 1: Backend URL -->
                <div class="space-y-3">
                    <label
                        for="backend-url"
                        class="flex items-center gap-2 text-sm font-medium text-gray-300"
                    >
                        <span
                            class="flex items-center justify-center w-5 h-5 rounded-full bg-white/10 text-[10px] font-bold text-white"
                            >1</span
                        >
                        Where is your website running?
                    </label>

                    <!-- Framework Presets -->
                    <div class="flex flex-wrap gap-2">
                        {#each presets as preset}
                            <button
                                on:click={() => applyPreset(preset)}
                                class="px-3 py-1.5 text-xs rounded-full border transition-all
                                    {backendUrl === preset.url
                                    ? 'bg-white/10 border-white/30 text-white'
                                    : 'bg-[#0a0a0a] border-[#222] text-gray-400 hover:border-[#444] hover:text-white'}"
                            >
                                {preset.name}
                            </button>
                        {/each}
                    </div>

                    <!-- URL Input -->
                    <div class="relative">
                        <div class="absolute left-3 top-1/2 -translate-y-1/2">
                            <Globe size={16} class="text-gray-500" />
                        </div>
                        <input
                            id="backend-url"
                            type="url"
                            bind:value={backendUrl}
                            on:input={() => (urlTouched = true)}
                            placeholder="http://localhost:3000"
                            class="w-full bg-[#0a0a0a] border rounded-lg pl-10 pr-10 py-3 text-white font-mono text-sm
                                   focus:outline-none transition-colors placeholder:text-gray-600
                                   {urlTouched && backendUrl
                                ? urlValidation.valid
                                    ? 'border-emerald-500/40 focus:border-emerald-500'
                                    : 'border-red-500/40 focus:border-red-500'
                                : 'border-[#222] focus:border-white/40'}"
                        />
                        {#if urlTouched && backendUrl}
                            <div
                                class="absolute right-3 top-1/2 -translate-y-1/2"
                                transition:scale={{ duration: 150 }}
                            >
                                {#if urlValidation.valid}
                                    <CheckCircle
                                        size={16}
                                        class="text-emerald-400"
                                    />
                                {:else}
                                    <AlertTriangle
                                        size={16}
                                        class="text-red-400"
                                    />
                                {/if}
                            </div>
                        {/if}
                    </div>
                    {#if urlTouched && !urlValidation.valid && backendUrl}
                        <p
                            class="text-red-400 text-xs"
                            transition:fade={{ duration: 150 }}
                        >
                            {urlValidation.error}
                        </p>
                    {/if}
                </div>

                <!-- Step 2: Security Level -->
                <div class="space-y-3">
                    <label
                        class="flex items-center gap-2 text-sm font-medium text-gray-300"
                    >
                        <span
                            class="flex items-center justify-center w-5 h-5 rounded-full bg-white/10 text-[10px] font-bold text-white"
                            >2</span
                        >
                        Choose security level
                    </label>

                    <div class="grid gap-3">
                        {#each Object.entries(levelDetails) as [key, detail]}
                            {@const level = key as SecurityLevel}
                            <button
                                on:click={() => (securityLevel = level)}
                                class="relative flex items-start gap-4 p-4 rounded-lg border text-left transition-all
                                    {securityLevel === level
                                    ? 'bg-white/5 border-white/20'
                                    : 'bg-[#0a0a0a] border-[#222] hover:border-[#333]'}"
                            >
                                <!-- Radio circle -->
                                <div
                                    class="mt-0.5 flex-shrink-0 w-4 h-4 rounded-full border-2 flex items-center justify-center transition-colors
                                    {securityLevel === level
                                        ? 'border-emerald-400'
                                        : 'border-[#444]'}"
                                >
                                    {#if securityLevel === level}
                                        <div
                                            class="w-2 h-2 rounded-full bg-emerald-400"
                                            transition:scale={{ duration: 150 }}
                                        ></div>
                                    {/if}
                                </div>
                                <div class="flex-1 space-y-1">
                                    <div class="flex items-center gap-2">
                                        <svelte:component
                                            this={detail.icon}
                                            size={14}
                                            class={securityLevel === level
                                                ? "text-white"
                                                : "text-gray-500"}
                                        />
                                        <span
                                            class="text-sm font-medium {securityLevel ===
                                            level
                                                ? 'text-white'
                                                : 'text-gray-300'}"
                                            >{detail.label}</span
                                        >
                                        {#if key === "moderate"}
                                            <span
                                                class="text-[10px] px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 rounded border border-emerald-500/20 uppercase tracking-wider"
                                                >Recommended</span
                                            >
                                        {/if}
                                    </div>
                                    <p
                                        class="text-xs text-gray-500 leading-relaxed"
                                    >
                                        {detail.desc}
                                    </p>
                                </div>
                                <span
                                    class="text-xs font-mono text-gray-600 flex-shrink-0 mt-0.5"
                                    >T={detail.threshold}</span
                                >
                            </button>
                        {/each}
                    </div>
                </div>

                <!-- Activate Button -->
                <button
                    on:click={activate}
                    disabled={!canActivate}
                    class="w-full flex items-center justify-center gap-3 px-6 py-4 rounded-lg font-medium text-sm transition-all
                        {canActivate
                        ? 'bg-white text-black hover:bg-gray-200 shadow-lg shadow-white/5'
                        : 'bg-[#111] text-gray-600 border border-[#222] cursor-not-allowed'}"
                >
                    <Rocket size={16} />
                    Activate Protection
                </button>

                <!-- Info footer -->
                <div
                    class="flex items-start gap-3 text-xs text-gray-600 bg-[#0a0a0a] border border-[#222] rounded-lg p-4"
                >
                    <Server
                        size={14}
                        class="text-gray-500 flex-shrink-0 mt-0.5"
                    />
                    <p>
                        SHIBUYA WAF will proxy all traffic through <code
                            class="text-gray-400">localhost:8080</code
                        > (HTTP) and apply 614 OWASP CRS rules plus ML anomaly detection
                        to every request. No config files, no restarts.
                    </p>
                </div>
            </div>
        {/if}
    </div>
</div>
