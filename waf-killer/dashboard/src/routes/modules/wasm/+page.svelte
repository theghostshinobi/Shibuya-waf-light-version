<script lang="ts">
    import { onMount } from "svelte";
    import { api, type WasmPluginInfo } from "$lib/api/client";
    import {
        Puzzle,
        Upload,
        Check,
        X,
        FileCode,
        RefreshCw,
        HardDrive,
        Hash,
    } from "lucide-svelte";
    import { fly, fade } from "svelte/transition";

    let plugins: WasmPluginInfo[] = [];
    let isLoading = true;
    let isDragging = false;
    let isUploading = false;
    let showToast = false;
    let toastMessage = "";
    let toastSuccess = true;

    onMount(async () => {
        await loadPlugins();
    });

    async function loadPlugins() {
        isLoading = true;
        try {
            plugins = await api.getWasmPlugins();
        } catch (e) {
            console.error("Failed to load WASM plugins:", e);
        } finally {
            isLoading = false;
        }
    }

    function formatBytes(bytes: number): string {
        if (bytes === 0) return "0 B";
        const k = 1024;
        const sizes = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
    }

    function handleDragOver(e: DragEvent) {
        e.preventDefault();
        isDragging = true;
    }

    function handleDragLeave(e: DragEvent) {
        e.preventDefault();
        isDragging = false;
    }

    async function handleDrop(e: DragEvent) {
        e.preventDefault();
        isDragging = false;

        const files = e.dataTransfer?.files;
        if (files && files.length > 0) {
            await uploadFile(files[0]);
        }
    }

    async function handleFileSelect(e: Event) {
        const input = e.target as HTMLInputElement;
        if (input.files && input.files.length > 0) {
            await uploadFile(input.files[0]);
        }
    }

    async function uploadFile(file: File) {
        if (!file.name.endsWith(".wasm")) {
            showToastMessage("Please select a .wasm file", false);
            return;
        }

        isUploading = true;
        try {
            const result = await api.uploadWasmPlugin(file);
            if (result.success) {
                showToastMessage(
                    `Plugin "${file.name}" uploaded successfully!`,
                    true,
                );
                // Wait a moment for file watcher to detect and load
                setTimeout(loadPlugins, 500);
            } else {
                showToastMessage(result.message || "Upload failed", false);
            }
        } catch (e) {
            showToastMessage("Upload failed: " + String(e), false);
        } finally {
            isUploading = false;
        }
    }

    function showToastMessage(message: string, success: boolean) {
        toastMessage = message;
        toastSuccess = success;
        showToast = true;
        setTimeout(() => {
            showToast = false;
        }, 3000);
    }
</script>

<div class="relative space-y-6 max-w-6xl mx-auto h-full px-4 py-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
        <div>
            <h2
                class="text-3xl font-bold tracking-tight text-white flex items-center gap-3"
            >
                <Puzzle class="text-purple-500" size={32} />
                WASM Modules
            </h2>
            <p class="text-gray-400 mt-1">
                Runtime-extensible WebAssembly plugins for custom security logic
            </p>
        </div>
        <button
            class="bg-[#111] border border-[#333] hover:border-purple-500/50 text-white px-4 py-2 rounded-md font-medium transition-colors flex items-center gap-2"
            on:click={loadPlugins}
        >
            <RefreshCw size={16} class={isLoading ? "animate-spin" : ""} />
            Refresh
        </button>
    </div>

    <!-- Upload Zone -->
    <div
        class="border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 cursor-pointer
           {isDragging
            ? 'border-purple-500 bg-purple-500/10'
            : 'border-[#333] hover:border-[#555] bg-[#0A0A0A]'}"
        on:dragover={handleDragOver}
        on:dragleave={handleDragLeave}
        on:drop={handleDrop}
        role="button"
        tabindex="0"
    >
        <input
            type="file"
            accept=".wasm"
            class="hidden"
            id="wasm-upload"
            on:change={handleFileSelect}
        />
        <label for="wasm-upload" class="cursor-pointer">
            <div class="flex flex-col items-center gap-4">
                {#if isUploading}
                    <div class="animate-pulse">
                        <Upload size={48} class="text-purple-500" />
                    </div>
                    <p class="text-gray-300 font-medium">Uploading...</p>
                {:else}
                    <div
                        class="w-16 h-16 rounded-full bg-[#111] border border-[#333] flex items-center justify-center
                      {isDragging ? 'border-purple-500 bg-purple-500/20' : ''}"
                    >
                        <Upload size={28} class="text-gray-400" />
                    </div>
                    <div>
                        <p class="text-gray-200 font-medium">
                            Drag & Drop your <span class="text-purple-400"
                                >.wasm</span
                            > plugin here
                        </p>
                        <p class="text-gray-500 text-sm mt-1">
                            or click to browse files
                        </p>
                    </div>
                {/if}
            </div>
        </label>
    </div>

    <!-- Plugins List -->
    <div class="space-y-3">
        <h3
            class="text-sm font-medium text-gray-400 uppercase tracking-wider px-1"
        >
            Active Plugins ({plugins.length})
        </h3>

        {#if isLoading}
            <div
                class="bg-[#111] border border-[#222] rounded-lg p-8 text-center"
            >
                <RefreshCw
                    size={24}
                    class="text-gray-500 animate-spin mx-auto mb-3"
                />
                <p class="text-gray-500">Loading plugins...</p>
            </div>
        {:else if plugins.length === 0}
            <div
                class="bg-[#111] border border-[#222] rounded-lg p-8 text-center"
            >
                <FileCode size={48} class="text-gray-700 mx-auto mb-4" />
                <p class="text-gray-400 font-medium">No WASM plugins loaded</p>
                <p class="text-gray-600 text-sm mt-1">
                    Upload a .wasm file to extend WAF functionality
                </p>
            </div>
        {:else}
            {#each plugins as plugin (plugin.name)}
                <div
                    class="bg-[#111] border border-[#222] p-4 rounded-lg flex items-center justify-between hover:border-purple-500/30 transition-all"
                    in:fly={{ y: 10, duration: 200 }}
                >
                    <div class="flex items-center gap-4">
                        <div
                            class="h-12 w-12 rounded-lg bg-gradient-to-br from-purple-500/20 to-purple-600/10 flex items-center justify-center border border-purple-500/20"
                        >
                            <Puzzle size={24} class="text-purple-400" />
                        </div>
                        <div>
                            <div class="font-bold text-gray-200 font-mono">
                                {plugin.name}
                            </div>
                            <div
                                class="text-sm text-gray-500 flex items-center gap-3 mt-0.5"
                            >
                                <span class="flex items-center gap-1">
                                    <HardDrive size={12} />
                                    {formatBytes(plugin.size_bytes)}
                                </span>
                                <span class="flex items-center gap-1">
                                    <Hash size={12} />
                                    {plugin.hash}
                                </span>
                            </div>
                        </div>
                    </div>

                    <div class="flex items-center gap-2">
                        <span
                            class="px-2.5 py-1 rounded-full bg-emerald-900/20 text-emerald-400 text-xs uppercase border border-emerald-500/20 font-mono"
                        >
                            Active
                        </span>
                    </div>
                </div>
            {/each}
        {/if}
    </div>
</div>

<!-- Toast Notification -->
{#if showToast}
    <div
        transition:fly={{ y: 50, duration: 300 }}
        class="fixed bottom-8 left-1/2 -translate-x-1/2 px-6 py-3 rounded-full shadow-2xl flex items-center gap-3 z-[60]
           {toastSuccess
            ? 'bg-[#111] border border-emerald-500/30'
            : 'bg-[#111] border border-red-500/30'}"
    >
        {#if toastSuccess}
            <Check size={18} class="text-emerald-500" />
        {:else}
            <X size={18} class="text-red-500" />
        {/if}
        <span class="text-sm font-medium text-white">{toastMessage}</span>
    </div>
{/if}

<style>
    input[type="file"]:focus + label {
        outline: 2px solid rgb(168, 85, 247);
        outline-offset: 2px;
    }
</style>
