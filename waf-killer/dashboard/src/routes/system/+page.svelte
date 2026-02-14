<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import { 
        Server, 
        Globe, 
        Zap, 
        Cpu, 
        Activity, 
        ShieldCheck,
        Terminal
    } from "lucide-svelte";
    import { fly } from "svelte/transition";

    let systemInfo: any = null;
    let loading = true;
    let error = "";

    onMount(async () => {
        try {
            systemInfo = await api.getSystemInfo();
        } catch (e) {
            error = "Failed to load system info";
            console.error(e);
        } finally {
            loading = false;
        }
    });
</script>

<div class="space-y-6 max-w-6xl mx-auto h-full px-4 py-8">
    <div class="flex justify-between items-center mb-8">
        <div>
            <h2 class="text-3xl font-bold tracking-tight text-white flex items-center gap-3">
                <Server class="text-blue-500" size={32} />
                System Management
            </h2>
            <p class="text-gray-400 mt-1">Infrastructure status, hardware offload, and edge deployment info.</p>
        </div>
        
        {#if systemInfo}
        <div class="flex items-center gap-4 bg-[#111] px-4 py-2 rounded-lg border border-[#333]">
             <span class="text-gray-400 text-sm">OS:</span>
             <span class="text-gray-200 font-mono">{systemInfo.os}</span>
        </div>
        {/if}
    </div>

    {#if loading}
        <div class="flex justify-center py-20">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
    {:else if error}
        <div class="bg-red-900/20 border border-red-500/30 p-4 rounded-lg text-red-400">
            {error}
        </div>
    {:else}
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            <!-- Edge Deployment (Ep 14) -->
            <div 
                in:fly={{ y: 20, duration: 300, delay: 0 }}
                class="bg-[#111] border border-[#333] rounded-xl p-6 hover:border-blue-500/30 transition-all group"
            >
                <div class="flex items-center justify-between mb-6">
                    <div class="p-3 rounded-lg bg-blue-500/10 text-blue-500 group-hover:bg-blue-500/20 transition-colors">
                        <Globe size={24} />
                    </div>
                     <span class="text-xs uppercase font-mono text-gray-500">Episode 14</span>
                </div>
                
                <h3 class="text-lg font-bold text-white mb-1">Edge Deployment</h3>
                <p class="text-gray-400 text-sm mb-6">Global distribution status</p>
                
                <div class="space-y-4">
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">Provider</span>
                        <span class="text-gray-200 font-medium">{systemInfo.edge.provider}</span>
                    </div>
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">Region</span>
                        <div class="flex items-center gap-2">
                             <span class="w-2 h-2 rounded-full {systemInfo.edge.is_edge ? 'bg-emerald-500' : 'bg-yellow-500'}"></span>
                             <span class="text-gray-200 font-mono bg-[#222] px-2 py-0.5 rounded text-xs">
                                {systemInfo.edge.region.toUpperCase()}
                             </span>
                        </div>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-gray-400 text-sm">Mode</span>
                         <span class="px-2 py-1 rounded text-xs font-medium {systemInfo.edge.is_edge ? 'bg-emerald-900/30 text-emerald-400' : 'bg-gray-800 text-gray-400'}">
                            {systemInfo.edge.is_edge ? 'GLOBAL EDGE' : 'LOCAL DEV'}
                         </span>
                    </div>
                </div>
            </div>

            <!-- High Performance (Ep 19) -->
            <div 
                in:fly={{ y: 20, duration: 300, delay: 100 }}
                class="bg-[#111] border border-[#333] rounded-xl p-6 hover:border-amber-500/30 transition-all group"
            >
                <div class="flex items-center justify-between mb-6">
                    <div class="p-3 rounded-lg bg-amber-500/10 text-amber-500 group-hover:bg-amber-500/20 transition-colors">
                        <Zap size={24} />
                    </div>
                    <span class="text-xs uppercase font-mono text-gray-500">Episode 19</span>
                </div>
                
                <h3 class="text-lg font-bold text-white mb-1">High Performance</h3>
                <p class="text-gray-400 text-sm mb-6">Zero-copy & SIMD status</p>
                
                <div class="space-y-4">
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">SIMD Instructions</span>
                         <div class="flex items-center gap-2">
                            <span class="text-gray-200 font-mono text-sm">{systemInfo.high_perf.simd_enabled ? 'AVX2/SSE4.2' : 'None'}</span>
                            {#if systemInfo.high_perf.simd_enabled}
                                <Zap size={14} class="text-amber-500 fill-amber-500" />
                            {/if}
                         </div>
                    </div>
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">Zero-Copy Networking</span>
                        <span class="text-emerald-400 font-medium">Active</span>
                    </div>
                    <div class="flex justify-between items-center">
                        <span class="text-gray-400 text-sm">IO Driver</span>
                        <span class="text-gray-200 font-mono text-sm bg-[#222] px-2 py-1 rounded">
                            {systemInfo.high_perf.driver}
                        </span>
                    </div>
                </div>
            </div>

            <!-- DPAL (Ep 20) -->
            <div 
                in:fly={{ y: 20, duration: 300, delay: 200 }}
                class="bg-[#111] border border-[#333] rounded-xl p-6 hover:border-purple-500/30 transition-all group"
            >
                <div class="flex items-center justify-between mb-6">
                    <div class="p-3 rounded-lg bg-purple-500/10 text-purple-500 group-hover:bg-purple-500/20 transition-colors">
                        <Cpu size={24} />
                    </div>
                    <span class="text-xs uppercase font-mono text-gray-500">Episode 20</span>
                </div>
                
                <h3 class="text-lg font-bold text-white mb-1">DPAL Layer</h3>
                <p class="text-gray-400 text-sm mb-6">Data Plane Abstraction Layer</p>
                
                <div class="space-y-4">
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">Active Driver</span>
                        <div class="flex items-center gap-2">
                            <Terminal size={14} class="text-purple-400" />
                            <span class="text-gray-200 font-mono font-bold">
                                {systemInfo.dpal.active_driver}
                            </span>
                        </div>
                    </div>
                    <div class="flex justify-between items-center pb-3 border-b border-[#222]">
                        <span class="text-gray-400 text-sm">Hardware Offload</span>
                         <span class="px-2 py-1 rounded text-xs font-medium {systemInfo.dpal.offload_available ? 'bg-emerald-900/30 text-emerald-400' : 'bg-[#222] text-gray-500'}">
                            {systemInfo.dpal.offload_available ? 'AVAILABLE' : 'SOFTWARE EMULATION'}
                         </span>
                    </div>
                    <div class="w-full bg-[#222] h-1.5 rounded-full overflow-hidden mt-2">
                        <div class="bg-purple-500 h-full w-[100%] animate-pulse"></div>
                    </div>
                     <p class="text-xs text-center text-gray-500 mt-1">Abstraction Layer Active</p>
                </div>
            </div>

        </div>

        <!-- System Architecture Visualization (Mock) -->
        <div class="mt-8 bg-[#111] border border-[#333] rounded-xl p-6">
             <h3 class="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <Activity size={20} class="text-gray-400" />
                Architecture Overview
             </h3>
             <div class="relative h-32 bg-[#0A0A0A] rounded-lg border border-[#222] overflow-hidden flex items-center justify-center">
                 <div class="flex items-center gap-8 text-gray-500 text-sm font-mono">
                     <div class="flex flex-col items-center gap-2">
                         <Globe size={32} class="text-blue-500/50" />
                         <span>Internet</span>
                     </div>
                     <div class="h-px w-12 bg-gray-700"></div>
                     <div class="flex flex-col items-center gap-2 p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                         <ShieldCheck size={32} class="text-purple-500" />
                         <span class="text-purple-400">WAF (dp-layer)</span>
                     </div>
                      <div class="h-px w-12 bg-gray-700"></div>
                      <div class="flex flex-col items-center gap-2">
                         <Server size={32} class="text-gray-600" />
                         <span>Upstream</span>
                     </div>
                 </div>
             </div>
        </div>
    {/if}
</div>
