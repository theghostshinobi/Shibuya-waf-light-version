<script lang="ts">
    import { onMount } from "svelte";
    import * as echarts from "echarts";
    import type { TrafficTimeSeries } from "$lib/types";

    export let data: TrafficTimeSeries[] = [];
    export let height = 300;

    let chartContainer: HTMLDivElement;
    let chart: echarts.ECharts;

    $: if (chart && data) {
        updateChart(data);
    }

    function updateChart(data: TrafficTimeSeries[]) {
        const timestamps = data.map((d) =>
            new Date(d.timestamp).toLocaleTimeString(),
        );
        const total = data.map((d) => d.total_requests);
        const blocked = data.map((d) => d.blocked_requests);

        const option = {
            tooltip: {
                trigger: "axis",
            },
            legend: {
                data: ["Total Requests", "Blocked"],
            },
            grid: {
                left: "3%",
                right: "4%",
                bottom: "3%",
                containLabel: true,
            },
            xAxis: {
                type: "category",
                boundaryGap: false,
                data: timestamps,
            },
            yAxis: {
                type: "value",
            },
            series: [
                {
                    name: "Total Requests",
                    type: "line",
                    smooth: true,
                    data: total,
                    itemStyle: { color: "#3b82f6" },
                    areaStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: "rgba(59, 130, 246, 0.5)" },
                            { offset: 1, color: "rgba(59, 130, 246, 0.1)" },
                        ]),
                    },
                },
                {
                    name: "Blocked",
                    type: "line",
                    smooth: true,
                    data: blocked,
                    itemStyle: { color: "#ef4444" },
                },
            ],
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
