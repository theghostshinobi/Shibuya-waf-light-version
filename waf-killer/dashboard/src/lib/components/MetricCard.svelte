<script lang="ts">
  import * as Card from '$lib/components/ui/card';
  import { cn } from '$lib/utils';
  
  export let title: string;
  export let value: string | number;
  export let subValue: string | undefined = undefined;
  export let icon: any = undefined; 
  export let trend: 'up' | 'down' | 'neutral' = 'neutral';
  export let trendValue: string | undefined = undefined;
  export let className: string = '';
  export let variant: 'default' | 'danger' | 'warning' | 'success' = 'default';
  
  $: borderColor = variant === 'danger' ? 'border-red-200' :
                   variant === 'warning' ? 'border-yellow-200' :
                   variant === 'success' ? 'border-green-200' : '';
                   
  $: bgClass = variant === 'danger' ? 'bg-red-50 dark:bg-red-950/20' :
               variant === 'warning' ? 'bg-yellow-50 dark:bg-yellow-950/20' :
               variant === 'success' ? 'bg-green-50 dark:bg-green-950/20' : 'bg-card';
</script>

<Card.Root class={cn("overflow-hidden", borderColor, bgClass, className)}>
  <Card.Header class="flex flex-row items-center justify-between space-y-0 pb-2">
    <Card.Title class="text-sm font-medium">
      {title}
    </Card.Title>
    {#if icon}
      <svelte:component this={icon} class="h-4 w-4 text-muted-foreground" />
    {/if}
  </Card.Header>
  <Card.Content>
    <div class="text-2xl font-bold">{value}</div>
    {#if subValue || trendValue}
       <p class="text-xs text-muted-foreground mt-1 flex items-center gap-1">
         {#if trendValue}
           <span class={cn(
               trend === 'up' ? 'text-green-600' : 
               trend === 'down' ? 'text-red-600' : 'text-gray-600'
           )}>
             {trendValue}
           </span>
         {/if}
         {subValue}
       </p>
    {/if}
  </Card.Content>
</Card.Root>
