<script lang="ts">
  import { onMount } from "svelte";
  import * as Table from "$lib/components/ui/table";
  import { Badge } from "$lib/components/ui/badge";
  import { Button } from "$lib/components/ui/button";
  import type { RequestSummary } from "$lib/types";
  import { createEventDispatcher } from "svelte";

  export let requests: RequestSummary[] = [];
  export let loading: boolean = false;

  const dispatch = createEventDispatcher<{ click: RequestSummary }>();

  function formatTime(ts: number | null | undefined): string {
    if (!ts) return "-";
    return new Date(ts * 1000).toLocaleTimeString();
  }
</script>

<div class="rounded-md border">
  <Table.Root>
    <Table.Header>
      <Table.Row>
        <Table.Head>Time</Table.Head>
        <Table.Head>Client IP</Table.Head>
        <Table.Head>Method</Table.Head>
        <Table.Head>URL</Table.Head>
        <Table.Head>Action</Table.Head>
        <Table.Head>Scores</Table.Head>
        <Table.Head class="text-right">Latency</Table.Head>
        <Table.Head class="text-right">Actions</Table.Head>
      </Table.Row>
    </Table.Header>
    <Table.Body>
      {#if loading}
        <Table.Row>
          <Table.Cell colspan={8} class="text-center h-24"
            >Loading...</Table.Cell
          >
        </Table.Row>
      {:else if requests.length === 0}
        <Table.Row>
          <Table.Cell colspan={8} class="text-center h-24"
            >No requests found.</Table.Cell
          >
        </Table.Row>
      {:else}
        {#each requests as req (req.id)}
          <Table.Row
            class="cursor-pointer hover:bg-muted/50"
            on:click={() => dispatch("click", req)}
          >
            <Table.Cell>{formatTime(req.timestamp)}</Table.Cell>
            <Table.Cell>{req.client_ip}</Table.Cell>
            <Table.Cell
              ><Badge variant="outline">{req.method}</Badge></Table.Cell
            >
            <Table.Cell
              class="font-mono text-xs max-w-[200px] truncate"
              title={req.url}
            >
              {req.url}
            </Table.Cell>
            <Table.Cell>
              <Badge
                variant={req.action === "BLOCK" ? "destructive" : "default"}
              >
                {req.action}
              </Badge>
            </Table.Cell>
            <Table.Cell>
              <div class="flex flex-col text-xs">
                <span>CRS: {req.crs_score ?? "-"}</span>
                <span>ML: {(req.ml_score || 0).toFixed(2)}</span>
              </div>
            </Table.Cell>
            <Table.Cell class="text-right">{req.latency_ms}ms</Table.Cell>
            <Table.Cell class="text-right">
              <Button
                variant="ghost"
                size="sm"
                on:click={(e) => {
                  e.stopPropagation();
                  dispatch("click", req);
                }}
              >
                View
              </Button>
            </Table.Cell>
          </Table.Row>
        {/each}
      {/if}
    </Table.Body>
  </Table.Root>
</div>
