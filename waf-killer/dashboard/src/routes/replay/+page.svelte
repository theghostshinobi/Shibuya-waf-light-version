<script lang="ts">
    import api from "$lib/api/client";
    import {
        Card,
        CardHeader,
        CardTitle,
        CardContent,
    } from "$lib/components/ui/card";
    import { Button } from "$lib/components/ui/button";
    import { Input } from "$lib/components/ui/input";
    import { Badge } from "$lib/components/ui/badge";
    import { Play, RotateCcw, Activity } from "lucide-svelte";

    let policy = "";
    let from = "";
    let to = "";
    let replaying = false;
    let report = null;

    async function handleReplay() {
        replaying = true;
        try {
            const fromTime = from ? new Date(from).getTime() : 0;
            const toTime = to ? new Date(to).getTime() : 0;
            report = await api.replayTraffic(policy, fromTime, toTime);
        } catch (e) {
            console.error("Replay failed", e);
        } finally {
            replaying = false;
        }
    }
</script>

```
<div class="container mx-auto p-6 space-y-6">
    <div class="flex justify-between items-center">
        <h1 class="text-3xl font-bold">Traffic Replay</h1>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Configuration -->
        <Card class="lg:col-span-1">
            <CardHeader>
                <CardTitle>Replay Configuration</CardTitle>
            </CardHeader>
            <CardContent class="space-y-4">
                <div class="space-y-2">
                    <label class="text-sm font-medium">Time Range</label>
                    <div class="grid grid-cols-2 gap-2">
                        <Input
                            type="datetime-local"
                            bind:value={from}
                            placeholder="From"
                        />
                        <Input
                            type="datetime-local"
                            bind:value={to}
                            placeholder="To"
                        />
                    </div>
                </div>

                <div class="space-y-2">
                    <label class="text-sm font-medium"
                        >Shadow Policy (YAML)</label
                    >
                    <textarea
                        bind:value={policy}
                        placeholder="Paste policy YAML here..."
                        class="flex min-h-[300px] w-full rounded-md border border-zinc-800 bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-zinc-500 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-400 disabled:cursor-not-allowed disabled:opacity-50 font-mono text-xs"
                    ></textarea>
                </div>

                <Button
                    class="w-full"
                    on:click={handleReplay}
                    disabled={replaying}
                >
                    {#if replaying}
                        <RotateCcw class="mr-2 h-4 w-4 animate-spin" />
                        Replaying...
                    {:else}
                        <Play class="mr-2 h-4 w-4" />
                        Start Replay
                    {/if}
                </Button>
            </CardContent>
        </Card>

        <!-- Results -->
        <div class="lg:col-span-2 space-y-6">
            {#if report}
                <!-- Replay Summary -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Card>
                        <CardContent class="pt-6">
                            <div class="text-center">
                                <div class="text-3xl font-bold">
                                    {report.total_requests.toLocaleString()}
                                </div>
                                <div class="text-sm text-muted-foreground">
                                    Requests Replayed
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardContent class="pt-6">
                            <div class="text-center">
                                <div class="text-3xl font-bold text-red-500">
                                    {report.new_blocks}
                                </div>
                                <div
                                    class="text-sm text-muted-foreground text-red-500/80"
                                >
                                    New Blocks
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                    <Card>
                        <CardContent class="pt-6">
                            <div class="text-center">
                                <div class="text-3xl font-bold text-green-500">
                                    {report.new_allows}
                                </div>
                                <div
                                    class="text-sm text-muted-foreground text-green-500/80"
                                >
                                    New Allows
                                </div>
                            </div>
                        </CardContent>
                    </Card>
                </div>

                <Card>
                    <CardHeader>
                        <CardTitle>Replay Details</CardTitle>
                    </CardHeader>
                    <CardContent>
                        <p class="text-sm text-muted-foreground mb-4">
                            Decisions remained unchanged for {(
                                (report.unchanged / report.total_requests) *
                                100
                            ).toFixed(1)}% of processed traffic.
                        </p>

                        <div class="space-y-4">
                            <div class="rounded-md border p-4 bg-muted/30">
                                <h4 class="text-sm font-semibold mb-2">
                                    Example Changes
                                </h4>
                                <div class="space-y-2">
                                    <div
                                        class="text-xs flex justify-between items-center p-2 rounded bg-background border"
                                    >
                                        <span class="font-mono"
                                            >POST /v1/auth/login</span
                                        >
                                        <Badge variant="destructive"
                                            >NEW BLOCK</Badge
                                        >
                                    </div>
                                    <div
                                        class="text-xs flex justify-between items-center p-2 rounded bg-background border"
                                    >
                                        <span class="font-mono"
                                            >GET /search?q=%27+OR+1=1</span
                                        >
                                        <Badge variant="destructive"
                                            >NEW BLOCK</Badge
                                        >
                                    </div>
                                </div>
                            </div>
                        </div>
                    </CardContent>
                </Card>
            {:else}
                <div
                    class="h-full flex flex-col items-center justify-center border-2 border-dashed rounded-lg p-12 text-center text-muted-foreground"
                >
                    <Activity class="h-12 w-12 mb-4 opacity-20" />
                    <p>
                        Configure a time range and policy to start replaying
                        traffic.
                    </p>
                </div>
            {/if}
        </div>
    </div>
</div>
