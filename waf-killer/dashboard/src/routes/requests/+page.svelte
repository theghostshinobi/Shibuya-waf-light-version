<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { api, type RequestLog } from "$lib/api/client";
  import { Activity, Search, Pause, Play } from "lucide-svelte";

  let logs: RequestLog[] = [];
  let interval: any;
  let isPaused = false;
  let searchTerm = "";

  async function fetchLogs() {
    if (isPaused) return;
    try {
      logs = await api.getLogs();
    } catch (e) {
      console.error("Failed to fetch logs", e);
    }
  }

  onMount(() => {
    fetchLogs();
    interval = setInterval(fetchLogs, 2000);
  });

  onDestroy(() => {
    if (interval) clearInterval(interval);
  });

  $: filteredLogs = logs.filter(
    (l) =>
      l.uri.includes(searchTerm) ||
      l.client_ip.includes(searchTerm) ||
      l.reason.toLowerCase().includes(searchTerm.toLowerCase()),
  );
</script>

<div class="space-y-6">
  <div class="flex justify-between items-center">
    <div>
      <h2
        class="text-3xl font-bold tracking-tight text-white flex items-center gap-2"
      >
        <Activity class="text-blue-500" /> Live Traffic
      </h2>
      <p class="text-slate-400">Real-time inspection log stream</p>
    </div>

    <div class="flex items-center gap-4">
      <div class="relative">
        <Search
          class="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
          size={16}
        />
        <input
          type="text"
          bind:value={searchTerm}
          placeholder="Filter logs..."
          class="bg-slate-900 border border-slate-700 rounded-lg pl-10 pr-4 py-2 text-sm text-white focus:outline-none focus:border-blue-500 w-64 transition-colors"
        />
      </div>

      <button
        on:click={() => (isPaused = !isPaused)}
        class="p-2 rounded-lg border border-slate-700 hover:bg-slate-800 transition-colors text-slate-300"
        title={isPaused ? "Resume" : "Pause"}
      >
        {#if isPaused}
          <Play size={20} />
        {:else}
          <Pause size={20} />
        {/if}
      </button>
    </div>
  </div>

  <div
    class="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden shadow-xl"
  >
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead
          class="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-medium"
        >
          <tr>
            <th class="px-6 py-4">Time</th>
            <th class="px-6 py-4">IP Address</th>
            <th class="px-6 py-4">Method</th>
            <th class="px-6 py-4">URI</th>
            <th class="px-6 py-4">Status</th>
            <th class="px-6 py-4">Reason</th>
            <th class="px-6 py-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-800/50">
          {#each filteredLogs as log (log.id)}
            <tr
              class="hover:bg-slate-800/30 transition-colors {log.action ===
              'Block'
                ? 'bg-red-900/10'
                : ''}"
            >
              <td class="px-6 py-3 font-mono text-slate-400">
                {new Date(log.timestamp * 1000).toLocaleTimeString("en-US")}
              </td>
              <td class="px-6 py-3 font-mono text-blue-400">{log.client_ip}</td>
              <td class="px-6 py-3">
                <span
                  class="px-2 py-1 rounded text-xs font-bold
                  {log.method === 'GET'
                    ? 'bg-blue-900/30 text-blue-300'
                    : log.method === 'POST'
                      ? 'bg-green-900/30 text-green-300'
                      : 'bg-slate-800 text-slate-300'}"
                >
                  {log.method}
                </span>
              </td>
              <td
                class="px-6 py-3 text-slate-300 max-w-xs truncate"
                title={log.uri}>{log.uri}</td
              >
              <td class="px-6 py-3">
                <span
                  class="font-bold {log.status >= 400
                    ? 'text-red-400'
                    : 'text-green-400'}"
                >
                  {log.status}
                </span>
              </td>
              <td class="px-6 py-3 text-slate-400 italic">{log.reason}</td>
              <td class="px-6 py-3 text-right">
                <span
                  class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium border
                  {log.action === 'Block'
                    ? 'border-red-500/30 bg-red-500/10 text-red-400'
                    : log.action === 'Challenge'
                      ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                      : 'border-green-500/30 bg-green-500/10 text-green-400'}"
                >
                  {log.action}
                </span>
              </td>
            </tr>
          {:else}
            <tr>
              <td colspan="7" class="px-6 py-12 text-center text-slate-500">
                <div class="flex flex-col items-center gap-2">
                  <Activity size={32} class="opacity-20" />
                  <p>No traffic recorded yet</p>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
</div>
