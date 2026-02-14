<script lang="ts">
  import { onMount } from 'svelte';
  import * as Card from '$lib/components/ui/card';
  import { Button } from '$lib/components/ui/button';
  import { Badge } from '$lib/components/ui/badge';
  import { Check, X, AlertTriangle } from 'lucide-svelte';
  
  // Mock pending reviews
  let pendingReviews = [
      { 
          id: 'req_xyz_1', 
          method: 'POST', 
          url: '/api/login', 
          payload: '{"user": "admin\' --"}',
          mlPrediction: 'SQLi',
          confidence: 0.92 
      },
      { 
          id: 'req_xyz_2', 
          method: 'GET', 
          url: '/search?q=<script>alert(1)<\\/script>', 
          payload: '',
          mlPrediction: 'XSS',
          confidence: 0.88 
      }
  ];
  
  function handleFeedback(id: string, correct: boolean) {
      console.log(`Feedback for ${id}: ${correct ? 'Correct' : 'Incorrect'}`);
      pendingReviews = pendingReviews.filter(r => r.id !== id);
  }
</script>

<div class="container mx-auto p-6 space-y-6">
  <div class="flex items-center gap-4">
      <h1 class="text-2xl font-bold">ML Feedback Loop</h1>
      {#if pendingReviews.length > 0}
         <Badge variant="destructive">{pendingReviews.length} Pending</Badge>
      {/if}
  </div>
  
  <div class="bg-blue-50 dark:bg-blue-950/20 p-4 rounded-lg flex items-start gap-3 text-blue-800 dark:text-blue-200">
     <AlertTriangle class="h-5 w-5 mt-0.5" />
     <div>
       <h3 class="font-semibold">Help train the model</h3>
       <p class="text-sm opacity-90">Review these borderline requests to improve detection accuracy. Your feedback is fed back into the training loop.</p>
     </div>
  </div>

  <div class="space-y-4">
    {#each pendingReviews as item (item.id)}
      <Card.Root>
        <Card.Header>
           <div class="flex justify-between items-start">
              <div>
                  <Card.Title class="font-mono text-base flex items-center gap-2">
                     <Badge>{item.method}</Badge> {item.url}
                  </Card.Title>
                  <Card.Description class="mt-2">
                     Model predicts: <span class="font-bold text-orange-600">{item.mlPrediction}</span> 
                     ({(item.confidence * 100).toFixed(0)}% confidence)
                  </Card.Description>
              </div>
           </div>
        </Card.Header>
        <Card.Content>
           <pre class="bg-muted p-2 rounded text-xs overflow-x-auto">{item.payload || '(No Payload)'}</pre>
        </Card.Content>
        <Card.Footer class="flex gap-2 justify-end bg-muted/20 p-4">
           <Button variant="outline" size="sm" on:click={() => handleFeedback(item.id, false)}>
              <X class="mr-2 h-4 w-4" /> False Positive
           </Button>
           <Button variant="default" size="sm" class="bg-green-600 hover:bg-green-700" on:click={() => handleFeedback(item.id, true)}>
              <Check class="mr-2 h-4 w-4" /> Confirm Attack
           </Button>
        </Card.Footer>
      </Card.Root>
    {/each}
    
    {#if pendingReviews.length === 0}
       <div class="text-center py-12 text-muted-foreground">
          <Check class="mx-auto h-12 w-12 text-green-500 mb-4" />
          <h3 class="text-lg font-medium">All caught up!</h3>
          <p>No requests pending review.</p>
       </div>
    {/if}
  </div>
</div>
