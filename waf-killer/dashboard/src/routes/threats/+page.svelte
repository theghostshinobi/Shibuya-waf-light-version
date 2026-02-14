<script lang="ts">
    import { onMount } from "svelte";
    import * as Card from "$lib/components/ui/card";
    import { Badge } from "$lib/components/ui/badge";
    import { Input } from "$lib/components/ui/input";
    import {
        Search,
        Globe,
        ShieldAlert,
        Crosshair,
        Loader2,
        RefreshCw,
        Plus,
        Trash2,
        Ban,
        Shield,
    } from "lucide-svelte";
    import { api } from "$lib/api/client";

    let searchIp = "";
    let threatData: any = null;
    let loading = false;
    let error: string | null = null;

    // Feeds from API
    let feeds: Array<{
        name: string;
        count: number;
        status: string;
        last_updated?: string;
    }> = [];
    let feedsLoading = true;
    let feedsError: string | null = null;

    // Blacklist management
    let blacklistIp = "";
    let blacklistReason = "";
    let blacklistDuration = 3600;
    let addingToBlacklist = false;
    let removingIp = "";
    let blacklistMsg = "";
    let blacklistMsgType: "success" | "error" = "success";

    onMount(async () => {
        await loadFeeds();
    });

    async function loadFeeds() {
        feedsLoading = true;
        feedsError = null;
        try {
            feeds = await api.getThreatFeeds();
        } catch (e) {
            console.error("Failed to load threat feeds", e);
            feedsError = "Failed to load feeds";
            feeds = [{ name: "Threat Intel", count: 0, status: "Error" }];
        } finally {
            feedsLoading = false;
        }
    }

    async function handleKeydown(e: KeyboardEvent) {
        if (e.key === "Enter") await doLookup();
    }

    async function doLookup() {
        if (!searchIp) return;
        loading = true;
        error = null;
        threatData = null;
        try {
            threatData = await api.lookupIp(searchIp);
        } catch (e) {
            console.error(e);
            error = "Lookup failed or IP invalid";
        } finally {
            loading = false;
        }
    }

    async function addToBlacklist() {
        if (!blacklistIp) return;
        addingToBlacklist = true;
        blacklistMsg = "";
        try {
            const res = await api.addToBlacklist(
                blacklistIp,
                blacklistReason || undefined,
                blacklistDuration || undefined,
            );
            if (res.success) {
                blacklistMsg = `✅ ${blacklistIp} added to blacklist`;
                blacklistMsgType = "success";
                blacklistIp = "";
                blacklistReason = "";
            } else {
                blacklistMsg = "❌ Failed to add to blacklist";
                blacklistMsgType = "error";
            }
        } catch (e: any) {
            blacklistMsg = `❌ ${e.message}`;
            blacklistMsgType = "error";
        } finally {
            addingToBlacklist = false;
            setTimeout(() => (blacklistMsg = ""), 4000);
        }
    }

    async function removeFromBlacklist() {
        if (!removingIp) return;
        try {
            const res = await api.removeFromBlacklist(removingIp);
            if (res.success) {
                blacklistMsg = `✅ ${removingIp} removed from blacklist`;
                blacklistMsgType = "success";
                removingIp = "";
            }
        } catch (e: any) {
            blacklistMsg = `❌ ${e.message}`;
            blacklistMsgType = "error";
        }
        setTimeout(() => (blacklistMsg = ""), 4000);
    }
</script>

<div class="container mx-auto p-6 space-y-6">
    <div class="flex justify-between items-center">
        <h1 class="text-2xl font-bold">Threat Intelligence</h1>
        <Badge variant="outline" class="bg-primary/10 text-primary"
            >LAYER 7 PROTECTED</Badge
        >
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- IP Investigation -->
        <Card.Root class="md:col-span-2">
            <Card.Header>
                <Card.Title>IP Investigation</Card.Title>
            </Card.Header>
            <Card.Content class="space-y-6">
                <div class="relative">
                    <Search
                        class="absolute left-3 top-3 h-4 w-4 text-muted-foreground"
                    />
                    <Input
                        placeholder="Enter IP address (e.g. 1.2.3.4)"
                        class="pl-10"
                        bind:value={searchIp}
                        on:keydown={handleKeydown}
                    />
                </div>

                {#if loading}
                    <div class="flex justify-center p-8 text-muted-foreground">
                        <Loader2 class="animate-spin mr-2" /> Searching Global Rep...
                    </div>
                {:else if error}
                    <div
                        class="text-red-500 p-4 border border-red-900/20 bg-red-900/10 rounded-lg"
                    >
                        {error}
                    </div>
                {:else if threatData}
                    <div class="rounded-lg border p-4 bg-muted/20 space-y-4">
                        <div class="flex justify-between items-center">
                            <span class="font-bold text-lg"
                                >{threatData.ip}</span
                            >
                            {#if threatData.status === "Clean"}
                                <Badge
                                    variant="outline"
                                    class="text-green-500 border-green-500"
                                    >CLEAN</Badge
                                >
                            {:else}
                                <Badge variant="destructive"
                                    >{threatData.threat_type || "MALICIOUS"} ({threatData.reputation_score ||
                                        "High Conf"})</Badge
                                >
                            {/if}
                        </div>
                        <div class="grid grid-cols-2 gap-4 text-sm">
                            <div class="flex flex-col">
                                <span class="text-muted-foreground mb-1"
                                    >Source</span
                                >
                                <span class="flex items-center gap-2"
                                    >{threatData.source || "Internal DB"}</span
                                >
                            </div>
                        </div>
                        {#if threatData.reason}
                            <div class="mt-2 text-sm text-muted-foreground">
                                Reason: {threatData.reason}
                            </div>
                        {/if}
                    </div>
                {:else}
                    <div class="text-center py-12 text-muted-foreground">
                        <Crosshair class="mx-auto h-12 w-12 opacity-20 mb-4" />
                        <p>Search an IP to see real-time threat data.</p>
                    </div>
                {/if}
            </Card.Content>
        </Card.Root>

        <div class="space-y-6">
            <!-- Active Feeds -->
            <Card.Root>
                <Card.Header>
                    <Card.Title class="text-base">Active Feeds</Card.Title>
                </Card.Header>
                <Card.Content class="p-0">
                    <div class="divide-y">
                        {#each feeds as feed}
                            <div class="p-4 flex justify-between items-center">
                                <div>
                                    <p class="font-medium text-sm">
                                        {feed.name}
                                    </p>
                                    <p class="text-xs text-muted-foreground">
                                        {feed.count} IOCs
                                    </p>
                                </div>
                                <Badge
                                    variant="outline"
                                    class="text-[10px] text-green-600 border-green-200"
                                    >ACTIVE</Badge
                                >
                            </div>
                        {/each}
                    </div>
                </Card.Content>
            </Card.Root>
        </div>
    </div>

    <!-- ════════ IP Blacklist Management ════════ -->
    <Card.Root>
        <Card.Header>
            <Card.Title class="flex items-center gap-2">
                <Ban class="text-red-500" size={20} />
                IP Blacklist Management
            </Card.Title>
        </Card.Header>
        <Card.Content class="space-y-4">
            {#if blacklistMsg}
                <div
                    class="p-3 rounded-lg text-sm font-medium {blacklistMsgType ===
                    'success'
                        ? 'bg-green-900/20 text-green-400 border border-green-900/30'
                        : 'bg-red-900/20 text-red-400 border border-red-900/30'}"
                >
                    {blacklistMsg}
                </div>
            {/if}

            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Add to Blacklist -->
                <div class="space-y-3">
                    <h3
                        class="text-sm font-semibold text-muted-foreground uppercase tracking-wider"
                    >
                        Add IP to Blacklist
                    </h3>
                    <Input
                        placeholder="IP Address (e.g. 192.168.1.100)"
                        bind:value={blacklistIp}
                    />
                    <Input
                        placeholder="Reason (optional)"
                        bind:value={blacklistReason}
                    />
                    <div class="flex items-center gap-3">
                        <select
                            bind:value={blacklistDuration}
                            class="bg-background border rounded-md px-3 py-2 text-sm flex-1"
                        >
                            <option value={3600}>1 Hour</option>
                            <option value={86400}>24 Hours</option>
                            <option value={604800}>7 Days</option>
                            <option value={2592000}>30 Days</option>
                            <option value={0}>Permanent</option>
                        </select>
                        <button
                            class="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50"
                            on:click={addToBlacklist}
                            disabled={addingToBlacklist || !blacklistIp}
                        >
                            {#if addingToBlacklist}
                                <Loader2 class="animate-spin" size={14} />
                            {:else}
                                <Plus size={14} />
                            {/if}
                            Block IP
                        </button>
                    </div>
                </div>

                <!-- Remove from Blacklist -->
                <div class="space-y-3">
                    <h3
                        class="text-sm font-semibold text-muted-foreground uppercase tracking-wider"
                    >
                        Remove IP from Blacklist
                    </h3>
                    <Input
                        placeholder="IP Address to unblock"
                        bind:value={removingIp}
                    />
                    <button
                        class="flex items-center gap-2 px-4 py-2 bg-zinc-700 hover:bg-zinc-600 text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50"
                        on:click={removeFromBlacklist}
                        disabled={!removingIp}
                    >
                        <Trash2 size={14} />
                        Remove from Blacklist
                    </button>
                </div>
            </div>
        </Card.Content>
    </Card.Root>
</div>

<style>
    :global(.lucide) {
        display: inline-block;
        vertical-align: middle;
    }
</style>
