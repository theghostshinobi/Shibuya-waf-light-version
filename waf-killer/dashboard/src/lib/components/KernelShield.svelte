<script lang="ts">
    import { onMount, onDestroy } from "svelte";
    import { fade, fly } from "svelte/transition";

    export let active = true;
    export let droppedCount = 0;

    let pulseInterval: any;
    let showPulse = false;

    // Neon pulse effect
    onMount(() => {
        if (active) {
            startPulse();
        }
    });

    $: if (active) {
        startPulse();
    } else {
        stopPulse();
    }

    function startPulse() {
        stopPulse();
        pulseInterval = setInterval(() => {
            showPulse = true;
            setTimeout(() => {
                showPulse = false;
            }, 1000);
        }, 3000);
    }

    function stopPulse() {
        if (pulseInterval) clearInterval(pulseInterval);
        showPulse = false;
    }

    onDestroy(() => {
        stopPulse();
    });

    function toggle() {
        active = !active;
    }

    function formatNumber(num: number): string {
        return new Intl.NumberFormat("en-US", {
            notation: "compact",
            maximumFractionDigits: 1,
        }).format(num);
    }
</script>

<div
    class="relative w-full max-w-[300px] aspect-square flex items-center justify-center"
>
    <!-- Outer Glow Ring -->
    <div
        class="absolute inset-0 rounded-full border-2 border-slate-700/50 transition-all duration-700
    {active ? 'border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.2)]' : ''}"
    ></div>

    <!-- Spinning Ring (Animation) -->
    {#if active}
        <div
            class="absolute inset-2 rounded-full border border-t-cyan-500 border-r-transparent border-b-cyan-500/50 border-l-transparent animate-spin-slow opacity-70"
        ></div>
        <div
            class="absolute inset-6 rounded-full border border-b-blue-500 border-l-transparent border-t-blue-500/50 border-r-transparent animate-reverse-spin opacity-50"
        ></div>
    {/if}

    <!-- Main Shield Body -->
    <div
        class="relative z-10 flex flex-col items-center justify-center cursor-pointer transition-all duration-300 transform hover:scale-105 active:scale-95"
        on:click={toggle}
        on:keydown={(e) => e.key === "Enter" && toggle()}
        role="button"
        tabindex="0"
    >
        <!-- Status Indicator Background -->
        <div
            class="w-40 h-40 rounded-full flex items-center justify-center transition-all duration-500
      {active
                ? 'bg-cyan-950/30 shadow-[0_0_30px_inset_rgba(6,182,212,0.2)]'
                : 'bg-slate-900 shadow-inner border border-slate-800'}"
        >
            <!-- Icon / Logo -->
            <div class="flex flex-col items-center gap-2">
                <div
                    class="text-4xl transition-all duration-300 {active
                        ? 'text-cyan-400 drop-shadow-[0_0_10px_rgba(6,182,212,0.8)]'
                        : 'text-slate-600'}"
                >
                    {#if active}
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            width="48"
                            height="48"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            class="lucide lucide-shield-check"
                            ><path
                                d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
                            /><path d="m9 12 2 2 4-4" /></svg
                        >
                    {:else}
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            width="48"
                            height="48"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="2"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            class="lucide lucide-shield-off"
                            ><path d="m2 2 20 20" /><path
                                d="M5 18c-1.3-.8-2-2-2-7V6a1 1 0 0 1 1-1c1.6 0 3.3-.9 4.7-2.1m3.6 0c1.3 1.1 3 2.1 4.7 2.1a1 1 0 0 1 1 1v2.5"
                            /><path d="M19.3 14c.4.9.7 1.9.7 4v.2" /></svg
                        >
                    {/if}
                </div>

                <div
                    class="font-bold text-sm tracking-wider uppercase {active
                        ? 'text-cyan-200'
                        : 'text-slate-500'}"
                >
                    eBPF KERNEL
                </div>

                <div
                    class="font-mono text-xs {active
                        ? 'text-cyan-500'
                        : 'text-slate-600'}"
                >
                    {active ? "ACTIVE" : "OFFLINE"}
                </div>
            </div>
        </div>
    </div>

    <!-- Stats Display (Bottom) -->
    <div class="absolute -bottom-8 flex flex-col items-center">
        <div
            class="text-xs text-slate-400 uppercase tracking-widest text-[0.65rem] mb-1"
        >
            Packets Dropped
        </div>
        <div
            class="font-mono text-xl font-bold transition-colors duration-300
         {active
                ? 'text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]'
                : 'text-slate-600'}"
        >
            {formatNumber(droppedCount)}
        </div>
    </div>

    <!-- Pulse Wave Effect -->
    {#if active && showPulse}
        <div
            class="absolute inset-0 rounded-full border border-cyan-500/50"
            in:fade={{ duration: 100 }}
            out:fade={{ duration: 800 }}
            style="animation: ping 1s cubic-bezier(0, 0, 0.2, 1) infinite;"
        ></div>
    {/if}
</div>

<style>
    @keyframes spin-slow {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }
    @keyframes reverse-spin {
        from {
            transform: rotate(360deg);
        }
        to {
            transform: rotate(0deg);
        }
    }
    .animate-spin-slow {
        animation: spin-slow 8s linear infinite;
    }
    .animate-reverse-spin {
        animation: reverse-spin 12s linear infinite;
    }
    @keyframes ping {
        75%,
        100% {
            transform: scale(1.5);
            opacity: 0;
        }
    }
</style>
