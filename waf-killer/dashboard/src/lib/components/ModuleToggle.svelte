<script lang="ts">
    export let enabled: boolean = true;
    export let label: string;
    export let description: string = "";
    export let onToggle: (enabled: boolean) => void = () => {};

    function handleToggle() {
        enabled = !enabled;
        onToggle(enabled);
    }
</script>

<div class="module-toggle" class:active={enabled}>
    <div class="toggle-content">
        <span class="toggle-label">{label}</span>
        {#if description}
            <span class="toggle-description">{description}</span>
        {/if}
    </div>
    <button
        class="switch"
        class:active={enabled}
        on:click={handleToggle}
        aria-label="Toggle {label}"
    >
        <span class="switch-thumb"></span>
    </button>
</div>

<style>
    .module-toggle {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1rem 1.25rem;
        background: rgba(30, 41, 59, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 0.75rem;
        transition: all 0.3s ease;
    }

    .module-toggle.active {
        border-color: rgba(6, 182, 212, 0.2);
        background: rgba(6, 182, 212, 0.05);
    }

    .toggle-content {
        display: flex;
        flex-direction: column;
        gap: 0.125rem;
    }

    .toggle-label {
        font-size: 0.875rem;
        font-weight: 600;
        color: #f1f5f9;
    }

    .toggle-description {
        font-size: 0.75rem;
        color: #64748b;
    }

    .switch {
        width: 44px;
        height: 24px;
        background: #334155;
        border: none;
        border-radius: 9999px;
        position: relative;
        cursor: pointer;
        transition: all 0.3s ease;
        flex-shrink: 0;
    }

    .switch.active {
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        box-shadow: 0 0 12px rgba(6, 182, 212, 0.35);
    }

    .switch-thumb {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 20px;
        height: 20px;
        background: #0f172a;
        border-radius: 50%;
        transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }

    .switch.active .switch-thumb {
        left: calc(100% - 22px);
    }
</style>
