<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import { Activity } from "lucide-svelte";

    let activities: any[] = [];
    let loading = true;

    onMount(async () => {
        try {
            activities = await api.getActivityFeed(50);
        } catch (e) {
            console.error(e);
        } finally {
            loading = false;
        }
    });

    function formatRelativeTime(dateStr: string) {
        const date = new Date(dateStr);
        const now = new Date();
        const diff = Math.floor((now.getTime() - date.getTime()) / 1000);

        if (diff < 60) return `${diff}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return date.toLocaleDateString();
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function formatAction(action: any) {
        if (typeof action === "string") return action;
        if (action.type) {
            return `${action.type}: ${JSON.stringify(action.data)}`;
        }
        return JSON.stringify(action);
    }
</script>

<div class="space-y-6 container mx-auto p-6">
    <div class="flex items-center gap-3">
        <h1 class="text-2xl font-bold tracking-tight">Activity Feed</h1>
        <span
            class="px-2 py-0.5 rounded-full bg-zinc-800 text-xs text-zinc-400 border border-zinc-700"
            >Audit Trail</span
        >
    </div>

    <div class="rounded-lg border border-zinc-800 bg-black/40 overflow-hidden">
        {#if loading}
            <div class="p-8 space-y-4">
                {#each Array(3) as _}
                    <div class="flex gap-4 animate-pulse">
                        <div class="w-8 h-8 rounded-full bg-zinc-800"></div>
                        <div class="flex-1 space-y-2">
                            <div class="h-4 bg-zinc-800 w-1/3 rounded"></div>
                            <div class="h-3 bg-zinc-800/50 w-1/4 rounded"></div>
                        </div>
                    </div>
                {/each}
            </div>
        {:else}
            <ul class="divide-y divide-zinc-800">
                {#each activities as activity}
                    <li class="p-6 hover:bg-zinc-900/20 transition-colors">
                        <div class="flex gap-4">
                            <div
                                class="mt-1 h-8 w-8 rounded-full bg-zinc-900 border border-zinc-700 flex items-center justify-center shrink-0"
                            >
                                <Activity class="h-4 w-4 text-zinc-400" />
                            </div>
                            <div class="flex-1 space-y-1">
                                <div class="flex items-center justify-between">
                                    <p
                                        class="text-sm font-medium text-zinc-200"
                                    >
                                        {activity.user_name || "System"}
                                    </p>
                                    <time
                                        class="text-xs text-zinc-500 font-mono"
                                        datetime={activity.created_at}
                                    >
                                        {formatRelativeTime(
                                            activity.created_at,
                                        )}
                                    </time>
                                </div>
                                <p class="text-sm text-zinc-400">
                                    {formatAction(activity.action)}
                                </p>
                            </div>
                        </div>
                    </li>
                {/each}
            </ul>
        {/if}
    </div>
</div>
