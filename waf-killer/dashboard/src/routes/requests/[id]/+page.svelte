<script lang="ts">
  import { page } from "$app/stores";
  import { onMount } from "svelte";
  import { api } from "$lib/api/client";
  import type { RequestSummary } from "$lib/types";
  import * as Card from "$lib/components/ui/card";
  import { Badge } from "$lib/components/ui/badge";
  import { Button } from "$lib/components/ui/button";
  import * as Tabs from "$lib/components/ui/tabs";
  import { Separator } from "$lib/components/ui/separator";
  import {
    ChevronLeft,
    ShieldAlert,
    ShieldCheck,
    Clock,
    Globe,
    Terminal,
  } from "lucide-svelte";

  let request: RequestSummary | null = null;
  let loading = true;

  onMount(async () => {
    const id = $page.params.id;
    try {
      request = await api.getRequest(id);
    } catch (e) {
      console.error(e);
    } finally {
      loading = false;
    }
  });

  function formatTimestamp(ts: number) {
    return new Date(ts * 1000).toLocaleString();
  }
</script>

<div class="container mx-auto p-6 space-y-6">
  <div class="flex items-center gap-4">
    <Button variant="ghost" size="icon" href="/requests">
      <ChevronLeft class="h-5 w-5" />
    </Button>
    <h1 class="text-2xl font-bold">Request Details</h1>
    {#if request}
      <Badge
        variant={request.action === "BLOCK" ? "destructive" : "default"}
        class="text-sm"
      >
        {request.action}
      </Badge>
    {/if}
  </div>

  {#if loading}
    <div class="flex items-center justify-center h-64">
      <div
        class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"
      ></div>
    </div>
  {:else if request}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Left Column: Summary & Metadata -->
      <div class="lg:col-span-2 space-y-6">
        <Card.Root>
          <Card.Header>
            <Card.Title>Summary</Card.Title>
          </Card.Header>
          <Card.Content class="space-y-4">
            <div class="grid grid-cols-2 gap-4">
              <div class="space-y-1">
                <span class="text-xs text-muted-foreground uppercase"
                  >Method</span
                >
                <p class="font-mono text-sm font-bold">{request.method}</p>
              </div>
              <div class="space-y-1">
                <span class="text-xs text-muted-foreground uppercase"
                  >Status</span
                >
                <p class="font-mono text-sm">200 OK (Clean)</p>
              </div>
              <div class="space-y-1">
                <span class="text-xs text-muted-foreground uppercase"
                  >Client IP</span
                >
                <p class="font-mono text-sm">{request.client_ip}</p>
              </div>
              <div class="space-y-1">
                <span class="text-xs text-muted-foreground uppercase"
                  >Timestamp</span
                >
                <p class="font-mono text-sm">
                  {formatTimestamp(request.timestamp)}
                </p>
              </div>
            </div>
            <Separator />
            <div class="space-y-1">
              <span class="text-xs text-muted-foreground uppercase">URL</span>
              <p class="font-mono text-sm break-all">{request.url}</p>
            </div>
          </Card.Content>
        </Card.Root>

        <Tabs.Root value="payload">
          <Tabs.List>
            <Tabs.Trigger value="payload">Payload</Tabs.Trigger>
            <Tabs.Trigger value="headers">Headers</Tabs.Trigger>
            <Tabs.Trigger value="raw">Raw HTTP</Tabs.Trigger>
          </Tabs.List>
          <Tabs.Content value="payload" class="mt-4">
            <Card.Root>
              <Card.Content class="p-4">
                <pre
                  class="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-[400px]"><code
                    >{JSON.stringify(
                      { query: "SELECT * FROM users", user: "admin' --" },
                      null,
                      2,
                    )}</code
                  ></pre>
              </Card.Content>
            </Card.Root>
          </Tabs.Content>
          <Tabs.Content value="headers" class="mt-4">
            <Card.Root>
              <Card.Content class="p-4 space-y-2">
                <div class="flex justify-between text-sm">
                  <span class="text-muted-foreground">User-Agent:</span>
                  <span class="font-mono">Mozilla/5.0...</span>
                </div>
                <div class="flex justify-between text-sm">
                  <span class="text-muted-foreground">Accept:</span>
                  <span class="font-mono">*/*</span>
                </div>
              </Card.Content>
            </Card.Root>
          </Tabs.Content>
        </Tabs.Root>
      </div>

      <!-- Right Column: Decision Engine -->
      <div class="space-y-6">
        <Card.Root
          class={request.action === "BLOCK"
            ? "border-red-200 bg-red-50/50"
            : "border-green-200 bg-green-50/50"}
        >
          <Card.Header>
            <Card.Title class="flex items-center gap-2">
              {#if request.action === "BLOCK"}
                <ShieldAlert class="text-red-600" /> WAF Decision: BLOCKED
              {:else}
                <ShieldCheck class="text-green-600" /> WAF Decision: ALLOWED
              {/if}
            </Card.Title>
          </Card.Header>
          <Card.Content class="space-y-4">
            <div class="space-y-2">
              <div class="flex justify-between items-center text-sm">
                <span>CRS Anomaly Score</span>
                <span class="font-bold">{request.crs_score}</span>
              </div>
              <div class="w-full bg-muted rounded-full h-2 overflow-hidden">
                <div
                  class="bg-red-500 h-full"
                  style="width: {Math.min(request.crs_score * 5, 100)}%"
                ></div>
              </div>
              <p class="text-xs text-muted-foreground">Threshold: 5</p>
            </div>

            <Separator />

            <div class="space-y-2">
              <div class="flex justify-between items-center text-sm">
                <span>ML Confidence</span>
                <span class="font-bold"
                  >{(request.ml_score * 100).toFixed(1)}%</span
                >
              </div>
              <div class="w-full bg-muted rounded-full h-2 overflow-hidden">
                <div
                  class="bg-orange-500 h-full"
                  style="width: {request.ml_score * 100}%"
                ></div>
              </div>
              <p class="text-xs text-muted-foreground">
                Pattern matched: SQL Injection
              </p>
            </div>
          </Card.Content>
          <Card.Footer>
            <Button variant="outline" class="w-full"
              >Mark as False Positive</Button
            >
          </Card.Footer>
        </Card.Root>

        <Card.Root>
          <Card.Header>
            <Card.Title class="text-sm font-medium">Matched Rules</Card.Title>
          </Card.Header>
          <Card.Content class="p-0">
            <div class="divide-y">
              <div class="p-4 space-y-1">
                <Badge variant="outline" class="text-[10px]">942100</Badge>
                <p class="text-sm">SQL Injection detected via libinjection</p>
              </div>
            </div>
          </Card.Content>
        </Card.Root>
      </div>
    </div>
  {:else}
    <p>Request not found.</p>
  {/if}
</div>
