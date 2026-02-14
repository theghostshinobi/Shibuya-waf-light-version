<script lang="ts">
  import { requestsStore } from '$lib/stores/requests';
  import RequestTable from '$lib/components/RequestTable.svelte';
  
  export let limit = 10;
  
  $: recentItems = $requestsStore.items.slice(0, limit);
</script>

<div class="space-y-4">
  <RequestTable requests={recentItems} loading={false} />
</div>
