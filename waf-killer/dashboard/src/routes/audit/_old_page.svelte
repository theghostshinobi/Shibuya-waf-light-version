<script lang="ts">
    import api from "$lib/api/client";

    let startDate = new Date().toISOString().split("T")[0];
    let endDate = new Date().toISOString().split("T")[0];

    async function downloadAuditLog() {
        try {
            const blob = await api.exportAuditLog(
                startDate + "T00:00:00Z",
                endDate + "T23:59:59Z",
            );
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `audit-${startDate}-${endDate}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (e) {
            console.error("Failed to export audit log", e);
            alert("Export failed");
        }
    }
</script>

<div class="space-y-6 p-6">
    <h1 class="text-2xl font-bold">Audit Logs</h1>

    <div class="bg-white shadow rounded-lg p-6">
        <p class="text-gray-500 mb-4">
            Export compliance-ready audit logs in CSV format.
        </p>

        <div class="flex gap-4 items-end">
            <div>
                <label class="block text-sm font-medium text-gray-700"
                    >From</label
                >
                <input
                    type="date"
                    bind:value={startDate}
                    class="mt-1 block border border-gray-300 rounded-md shadow-sm p-2"
                />
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700">To</label
                >
                <input
                    type="date"
                    bind:value={endDate}
                    class="mt-1 block border border-gray-300 rounded-md shadow-sm p-2"
                />
            </div>

            <button
                class="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-900"
                on:click={downloadAuditLog}
            >
                Export CSV
            </button>
        </div>
    </div>
</div>
