<script lang="ts">
  import { onMount } from 'svelte';
  import * as echarts from 'echarts';
  import type { PieSlice } from '$lib/types';
  
  export let data: PieSlice[] = [];
  export let height = 300;
  
  let chartContainer: HTMLDivElement;
  let chart: echarts.ECharts;
  
  $: if (chart && data) {
      updateChart(data);
  }
  
  function updateChart(data: PieSlice[]) {
      const option = {
          tooltip: {
              trigger: 'item'
          },
          legend: {
              top: '5%',
              left: 'center'
          },
          series: [
              {
                  name: 'Attack Type',
                  type: 'pie',
                  radius: ['40%', '70%'], // Donut chart
                  avoidLabelOverlap: false,
                  itemStyle: {
                      borderRadius: 10,
                      borderColor: '#fff',
                       borderWidth: 2
                  },
                  label: {
                      show: false,
                      position: 'center'
                  },
                  emphasis: {
                      label: {
                          show: true,
                          fontSize: 20,
                          fontWeight: 'bold'
                      }
                  },
                  labelLine: {
                      show: false
                  },
                  data: data
              }
          ]
      };
      
      chart.setOption(option);
  }
  
  onMount(() => {
      chart = echarts.init(chartContainer);
      if (data.length > 0) updateChart(data);
      
      const resizeObserver = new ResizeObserver(() => chart.resize());
      resizeObserver.observe(chartContainer);
      
      return () => {
          resizeObserver.disconnect();
          chart.dispose();
      };
  });
</script>

<div bind:this={chartContainer} style="height: {height}px; width: 100%;"></div>
