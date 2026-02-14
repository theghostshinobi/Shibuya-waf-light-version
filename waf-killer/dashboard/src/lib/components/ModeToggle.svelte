<script lang="ts">
    import { uiModeStore, type UIMode } from '$lib/stores/uiMode';
    import { Sparkles, Zap } from 'lucide-svelte';
    
    let mode: UIMode;
    uiModeStore.subscribe(value => mode = value);
</script>

<button 
    on:click={() => uiModeStore.toggle()}
    class="mode-toggle group"
    title={mode === 'simple' ? 'Switch to Advanced Mode' : 'Switch to Simple Mode'}
>
    <div class="toggle-track" class:advanced={mode === 'advanced'}>
        <div class="toggle-thumb" class:advanced={mode === 'advanced'}>
            {#if mode === 'simple'}
                <Zap size={12} class="text-slate-400" />
            {:else}
                <Sparkles size={12} class="text-cyan-400" />
            {/if}
        </div>
    </div>
    <span class="toggle-label">
        {#if mode === 'simple'}
            <span class="text-slate-400">Simple</span>
        {:else}
            <span class="text-gradient">God Mode</span>
        {/if}
    </span>
</button>

<style>
    .mode-toggle {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.5rem 1rem;
        background: rgba(30, 41, 59, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 9999px;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .mode-toggle:hover {
        background: rgba(30, 41, 59, 0.8);
        border-color: rgba(6, 182, 212, 0.3);
    }
    
    .toggle-track {
        width: 44px;
        height: 24px;
        background: #334155;
        border-radius: 9999px;
        position: relative;
        transition: all 0.3s ease;
    }
    
    .toggle-track.advanced {
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
    }
    
    .toggle-thumb {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 20px;
        height: 20px;
        background: #0f172a;
        border-radius: 9999px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }
    
    .toggle-thumb.advanced {
        left: calc(100% - 22px);
        box-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
    }
    
    .toggle-label {
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .text-gradient {
        background: linear-gradient(135deg, #06b6d4, #3b82f6, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
</style>
