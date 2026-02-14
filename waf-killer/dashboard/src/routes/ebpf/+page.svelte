<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import {
        Zap,
        Activity,
        ShieldCheck,
        Box,
        Ban,
        Loader2,
    } from "lucide-svelte";

    let enabled = true;
    let blockIp = "";
    let blocking = false;
    let blockMsg = "";
    let blockMsgType: "success" | "error" = "success";

    async function toggle() {
        try {
            const res = await api.toggleModule("ebpf");
            enabled = res.enabled;
        } catch (e) {
            console.error(e);
        }
    }

    async function kernelBlockIp() {
        if (!blockIp) return;
        blocking = true;
        blockMsg = "";
        try {
            const res = await api.blockIPKernel(blockIp);
            if (res.success) {
                blockMsg = `✅ ${blockIp} blocked at kernel level`;
                blockMsgType = "success";
                blockIp = "";
            } else {
                blockMsg = "❌ " + (res.message || "Block failed");
                blockMsgType = "error";
            }
        } catch (e: any) {
            blockMsg = "❌ " + e.message;
            blockMsgType = "error";
        } finally {
            blocking = false;
            setTimeout(() => (blockMsg = ""), 4000);
        }
    }
</script>

<div
    class="grid grid-cols-1 lg:grid-cols-2 gap-8 h-[calc(100vh-140px)] items-center"
>
    <!-- Left Panel: Status -->
    <div class="space-y-8">
        <div>
            <h2
                class="text-4xl font-bold tracking-tight text-white flex items-center gap-3 mb-2"
            >
                <Zap class="text-cyan-500" size={40} />
                eBPF Kernel Mode
            </h2>
            <p class="text-slate-400 text-lg">
                High-performance packet filtering at kernel level.
            </p>
        </div>

        <div
            class="bg-slate-900/50 border border-slate-800 rounded-2xl p-8 space-y-6"
        >
            <div class="flex justify-between items-center">
                <span class="text-slate-300 font-medium"
                    >Kernel Probe Status</span
                >
                <div class="flex items-center gap-2">
                    <div
                        class="w-2.5 h-2.5 rounded-full {enabled
                            ? 'bg-cyan-500 animate-pulse'
                            : 'bg-slate-600'}"
                    ></div>
                    <span
                        class="uppercase text-sm font-bold {enabled
                            ? 'text-cyan-500'
                            : 'text-slate-500'}"
                    >
                        {enabled ? "ATTACHED" : "DETACHED"}
                    </span>
                </div>
            </div>

            <div class="flex justify-between items-center">
                <span class="text-slate-300 font-medium">Master Switch</span>
                <button
                    on:click={toggle}
                    class="px-6 py-2 rounded-full font-bold text-sm transition-all duration-300
                {enabled
                        ? 'bg-cyan-500 text-cyan-950 hover:bg-cyan-400'
                        : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}"
                >
                    {enabled ? "DISABLE" : "ENABLE"}
                </button>
            </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
            <div class="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
                <div class="text-slate-400 text-sm uppercase mb-1">
                    Packets Dropped
                </div>
                <div class="text-3xl font-mono text-white">45.2K</div>
            </div>
            <div class="bg-slate-900/50 border border-slate-800 p-6 rounded-xl">
                <div class="text-slate-400 text-sm uppercase mb-1">
                    CPU Overhead
                </div>
                <div class="text-3xl font-mono text-white">0.05%</div>
            </div>
        </div>

        <!-- Kernel Block IP -->
        <div
            class="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 space-y-4"
        >
            <h3 class="text-slate-300 font-medium flex items-center gap-2">
                <Ban class="text-red-500" size={18} />
                Kernel-Level IP Block (XDP)
            </h3>
            {#if blockMsg}
                <div
                    class="text-sm {blockMsgType === 'success'
                        ? 'text-green-400'
                        : 'text-red-400'}"
                >
                    {blockMsg}
                </div>
            {/if}
            <div class="flex gap-3">
                <input
                    bind:value={blockIp}
                    placeholder="IP to block at kernel level"
                    class="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
                />
                <button
                    on:click={kernelBlockIp}
                    disabled={blocking || !blockIp}
                    class="px-4 py-2 rounded-lg font-bold text-sm transition-all bg-red-600 text-white hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                    {#if blocking}
                        <Loader2 size={14} class="animate-spin" />
                    {:else}
                        <Ban size={14} />
                    {/if}
                    Block
                </button>
            </div>
            <p class="text-xs text-slate-500">
                Drops packets at XDP level before they reach the network stack.
                Linux only.
            </p>
        </div>
    </div>

    <!-- Right Panel: Visualization -->
    <div
        class="relative flex items-center justify-center p-12 bg-slate-900/30 rounded-3xl border border-slate-800/50 min-h-[500px]"
    >
        <div class="absolute inset-0 bg-grid-pattern opacity-10"></div>

        <!-- Visualization -->
        <div
            class="relative z-10 w-full max-w-sm aspect-square flex items-center justify-center"
        >
            <div
                class="absolute inset-0 border-2 border-cyan-500/20 rounded-full animate-pulse"
            ></div>
            <div
                class="absolute inset-12 border-2 border-dashed border-cyan-500/40 rounded-full animate-spin-slow"
            ></div>

            {#if enabled}
                <div
                    class="text-cyan-500 drop-shadow-[0_0_15px_rgba(6,182,212,0.8)]"
                >
                    <ShieldCheck size={120} />
                </div>
            {:else}
                <div class="text-slate-700">
                    <Box size={120} />
                </div>
            {/if}
        </div>
    </div>
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
    .animate-spin-slow {
        animation: spin-slow 20s linear infinite;
    }
</style>
