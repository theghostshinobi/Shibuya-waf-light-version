<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import YamlEditor from "$lib/components/YamlEditor.svelte";
    import VisualEditor from "$lib/components/VisualEditor.svelte";
    import { toast } from "svelte-sonner";
    import YAML from "js-yaml";

    let config: any = null;
    let yamlContent = "";
    let mode: "visual" | "yaml" = "visual";
    let validationErrors: string[] = [];
    let isValidating = false;
    let isSaving = false;
    let isLoading = true;

    // Backups & Rollback
    let backups: any[] = [];
    let loadingBackups = false;
    let rollingBack = false;
    let showBackups = false;

    onMount(async () => {
        await loadConfig();
        await loadBackups();
    });

    async function loadConfig() {
        isLoading = true;
        try {
            config = await api.getConfig();
            yamlContent = jsToYaml(config);
        } catch (e: any) {
            console.error(e);
            alert("Failed to load configuration: " + e.message);
        } finally {
            isLoading = false;
        }
    }

    async function loadBackups() {
        loadingBackups = true;
        try {
            backups = await api.getConfigBackups();
        } catch (e) {
            console.error("Failed to load backups", e);
            backups = [];
        } finally {
            loadingBackups = false;
        }
    }

    async function rollback(timestamp: string) {
        if (
            !confirm(
                `Rollback config to backup from ${new Date(timestamp).toLocaleString()}? Current config will be replaced.`,
            )
        )
            return;
        rollingBack = true;
        try {
            const res = await api.rollbackConfig(timestamp);
            if (res.success) {
                alert("✅ " + res.message);
                await loadConfig();
                await loadBackups();
            } else {
                alert("❌ Rollback failed: " + res.message);
            }
        } catch (e: any) {
            alert("❌ Rollback error: " + e.message);
        } finally {
            rollingBack = false;
        }
    }

    async function validateConfig() {
        isValidating = true;
        validationErrors = [];
        try {
            const res = await fetch("/api/config/validate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    yaml: yamlContent,
                    check_connectivity: true,
                }),
            });
            const result = await res.json();
            if (!result.valid) {
                validationErrors = result.errors;
                return false;
            }
            return true;
        } catch (e) {
            console.error(e);
            return false;
        } finally {
            isValidating = false;
        }
    }

    async function saveConfig() {
        const valid = await validateConfig();
        if (!valid) {
            alert("Config invalid, check errors");
            return;
        }
        isSaving = true;
        try {
            const configObj = yamlToJs(yamlContent);
            const res = await api.updateConfig(configObj);
            if (res.success) {
                alert("Configuration Saved & Applied!");
                await loadConfig();
                await loadBackups();
            } else {
                alert("Failed to save configuration: " + res.message);
            }
        } catch (e: any) {
            alert("Error: " + e.message);
        } finally {
            isSaving = false;
        }
    }

    async function uploadYaml(event: Event) {
        const input = event.target as HTMLInputElement;
        const file = input.files?.[0];
        if (!file) return;
        const formData = new FormData();
        formData.append("yaml", file);
        const res = await fetch("/api/config/upload", {
            method: "POST",
            body: formData,
        });
        if (res.ok) {
            alert("YAML Uploaded!");
            await loadConfig();
        } else {
            alert("Upload failed");
        }
    }

    async function downloadYaml() {
        const blob = new Blob([yamlContent], { type: "text/yaml" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "waf-config.yaml";
        a.click();
        URL.revokeObjectURL(url);
    }

    function jsToYaml(obj: any): string {
        return YAML.dump(obj, { indent: 2 });
    }
    function yamlToJs(yaml: string): any {
        return YAML.load(yaml);
    }
    function formatTs(ts: string): string {
        try {
            return new Date(ts).toLocaleString();
        } catch {
            return ts;
        }
    }
</script>

<div class="config-page">
    <header>
        <h1>⚙️ Configuration</h1>
        <div class="actions">
            <div class="mode-switch">
                <button
                    on:click={() => (mode = "visual")}
                    class:active={mode === "visual"}>📝 Visual</button
                >
                <button
                    on:click={() => (mode = "yaml")}
                    class:active={mode === "yaml"}>📄 YAML</button
                >
            </div>
            <div class="spacer"></div>
            <div class="file-actions">
                <button
                    on:click={downloadYaml}
                    class="icon-btn"
                    title="Download">📥</button
                >
                <label class="icon-btn" title="Upload">
                    📤 <input
                        type="file"
                        accept=".yaml,.yml"
                        on:change={uploadYaml}
                        hidden
                    />
                </label>
            </div>
            <button
                on:click={validateConfig}
                disabled={isValidating}
                class="validate-btn"
            >
                {isValidating ? "⏳ Validating..." : "✅ Validate"}
            </button>
            <button on:click={saveConfig} class="primary" disabled={isSaving}>
                {isSaving ? "⏳ Saving..." : "💾 Save & Apply"}
            </button>
        </div>
    </header>

    {#if isLoading}
        <div class="loading">Loading configuration...</div>
    {:else}
        {#if validationErrors.length > 0}
            <div class="errors">
                <h3>❌ Validation Errors:</h3>
                <ul>
                    {#each validationErrors as error}<li>{error}</li>{/each}
                </ul>
            </div>
        {/if}

        <div class="editor-container">
            {#if mode === "visual"}
                <VisualEditor
                    bind:config
                    on:change={() => (yamlContent = jsToYaml(config))}
                />
            {:else}
                <YamlEditor bind:value={yamlContent} />
            {/if}
        </div>

        <!-- ════════ Config Backups & Rollback ════════ -->
        <div class="backups-section">
            <button
                class="backups-toggle"
                on:click={() => (showBackups = !showBackups)}
            >
                {showBackups ? "▼" : "▶"} Config Backups ({backups.length})
            </button>

            {#if showBackups}
                <div class="backups-list">
                    {#if loadingBackups}
                        <div class="loading">Loading backups...</div>
                    {:else if backups.length === 0}
                        <div class="no-backups">
                            No backups available yet. Backups are created
                            automatically when you save.
                        </div>
                    {:else}
                        <table class="backups-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Author</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each backups as backup}
                                    <tr>
                                        <td class="ts"
                                            >{formatTs(
                                                backup.timestamp ||
                                                    backup.created_at ||
                                                    backup,
                                            )}</td
                                        >
                                        <td
                                            >{backup.author ||
                                                backup.user ||
                                                "admin"}</td
                                        >
                                        <td>
                                            <button
                                                class="rollback-btn"
                                                on:click={() =>
                                                    rollback(
                                                        backup.timestamp ||
                                                            backup.created_at ||
                                                            backup,
                                                    )}
                                                disabled={rollingBack}
                                            >
                                                {rollingBack
                                                    ? "⏳..."
                                                    : "↩ Rollback"}
                                            </button>
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    {/if}
                </div>
            {/if}
        </div>
    {/if}
</div>

<style>
    .config-page {
        padding: 2rem;
        max-width: 1400px;
        margin: 0 auto;
        height: 100%;
    }
    header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
        flex-wrap: wrap;
        gap: 1rem;
    }
    h1 {
        margin: 0;
    }
    .actions {
        display: flex;
        gap: 1rem;
        align-items: center;
    }
    .mode-switch {
        display: flex;
        border: 1px solid #ddd;
        border-radius: 6px;
        overflow: hidden;
    }
    .mode-switch button {
        border: none;
        border-radius: 0;
        margin: 0;
    }
    .actions button {
        padding: 0.6rem 1.2rem;
        border: 1px solid #ddd;
        background: white;
        border-radius: 6px;
        cursor: pointer;
        font-weight: 500;
        transition: all 0.2s;
    }
    .actions button:hover {
        background: #f8f9fa;
    }
    .actions button.active {
        background: #007bff;
        color: white;
        border-color: #007bff;
    }
    .actions button.primary {
        background: #10b981;
        color: white;
        border-color: #10b981;
    }
    .actions button.primary:hover {
        background: #059669;
    }
    .errors {
        background: #fee2e2;
        border: 1px solid #fecaca;
        color: #991b1b;
        padding: 1rem;
        border-radius: 6px;
        margin-bottom: 1rem;
    }
    .errors ul {
        margin: 0.5rem 0 0 1.5rem;
    }
    .editor-container {
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        overflow: hidden;
        background: white;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .spacer {
        display: none;
    }
    @media (min-width: 768px) {
        .spacer {
            display: block;
            flex: 1;
        }
    }
    .loading {
        text-align: center;
        padding: 2rem;
        color: #666;
    }
    .file-actions {
        display: flex;
        gap: 0.5rem;
    }
    .icon-btn {
        padding: 0.6rem !important;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    /* Backups section */
    .backups-section {
        margin-top: 2rem;
    }
    .backups-toggle {
        background: #1e293b;
        color: #94a3b8;
        border: 1px solid #334155;
        padding: 0.75rem 1.25rem;
        border-radius: 8px;
        cursor: pointer;
        font-size: 0.875rem;
        font-weight: 600;
        width: 100%;
        text-align: left;
        transition: all 0.2s;
    }
    .backups-toggle:hover {
        background: #334155;
        color: #e2e8f0;
    }
    .backups-list {
        margin-top: 0.5rem;
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        overflow: hidden;
    }
    .backups-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.8125rem;
    }
    .backups-table th {
        text-align: left;
        padding: 0.75rem 1rem;
        color: #64748b;
        border-bottom: 1px solid #1e293b;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 0.6875rem;
        letter-spacing: 0.05em;
    }
    .backups-table td {
        padding: 0.75rem 1rem;
        color: #cbd5e1;
        border-bottom: 1px solid #1e293b;
    }
    .backups-table .ts {
        font-family: monospace;
        font-size: 0.75rem;
        color: #94a3b8;
    }
    .rollback-btn {
        background: rgba(239, 68, 68, 0.1);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.3);
        padding: 0.35rem 0.75rem;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.75rem;
        font-weight: 600;
        transition: all 0.2s;
    }
    .rollback-btn:hover {
        background: rgba(239, 68, 68, 0.2);
    }
    .rollback-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .no-backups {
        padding: 1.5rem;
        text-align: center;
        color: #64748b;
        font-size: 0.8125rem;
    }
</style>
