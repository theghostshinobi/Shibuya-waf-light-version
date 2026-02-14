<script lang="ts">
    import { goto } from "$app/navigation";
    import { authStore } from "$lib/stores/auth";
    import { Shield } from "lucide-svelte";

    let password = "";
    let error = "";
    let loading = false;

    async function handleLogin() {
        loading = true;
        error = "";

        // Small delay for UX
        await new Promise((r) => setTimeout(r, 500));

        const success = await authStore.login(password);

        if (success) {
            goto("/");
        } else {
            error = "Invalid password";
        }

        loading = false;
    }
</script>

<div class="login-wrapper">
    <!-- Animated background elements -->
    <div class="bg-effects">
        <div class="orb orb-1"></div>
        <div class="orb orb-2"></div>
        <div class="orb orb-3"></div>
        <div class="grid-overlay"></div>
    </div>

    <div class="login-card">
        <!-- Brand -->
        <div class="brand">
            <div class="logo-wrapper">
                <div class="logo-icon">
                    <Shield size={28} class="text-white" />
                </div>
                <div class="logo-glow"></div>
            </div>
            <h1>SHIBUYA WAF</h1>
            <p class="subtitle">Enterprise Security Dashboard</p>
        </div>

        {#if error}
            <div class="alert alert-error">
                <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="16"
                    height="16"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                >
                    <circle cx="12" cy="12" r="10" />
                    <line x1="12" y1="8" x2="12" y2="12" />
                    <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                {error}
            </div>
        {/if}

        <form on:submit|preventDefault={handleLogin}>
            <div class="input-group">
                <label for="password">Access Code</label>
                <input
                    id="password"
                    type="password"
                    placeholder="Enter password"
                    bind:value={password}
                    required
                    autofocus
                />
            </div>

            <button type="submit" class="btn-primary" disabled={loading}>
                {#if loading}
                    <span class="spinner"></span>
                    Authenticating...
                {:else}
                    Access Dashboard
                {/if}
            </button>
        </form>

        <p class="hint">Protected system. Unauthorized access prohibited.</p>
    </div>
</div>

<style>
    .login-wrapper {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #0f172a;
        position: relative;
        overflow: hidden;
    }

    .bg-effects {
        position: absolute;
        inset: 0;
        pointer-events: none;
    }

    .orb {
        position: absolute;
        border-radius: 50%;
        filter: blur(80px);
        opacity: 0.4;
    }

    .orb-1 {
        width: 400px;
        height: 400px;
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        top: -100px;
        right: -100px;
        animation: float1 15s ease-in-out infinite;
    }

    .orb-2 {
        width: 300px;
        height: 300px;
        background: linear-gradient(135deg, #8b5cf6, #3b82f6);
        bottom: -50px;
        left: -50px;
        animation: float2 18s ease-in-out infinite;
    }

    .orb-3 {
        width: 200px;
        height: 200px;
        background: linear-gradient(135deg, #06b6d4, #22c55e);
        top: 50%;
        left: 30%;
        animation: float3 20s ease-in-out infinite;
    }

    @keyframes float1 {
        0%,
        100% {
            transform: translate(0, 0) scale(1);
        }
        50% {
            transform: translate(-50px, 50px) scale(1.1);
        }
    }

    @keyframes float2 {
        0%,
        100% {
            transform: translate(0, 0) scale(1);
        }
        50% {
            transform: translate(30px, -30px) scale(0.9);
        }
    }

    @keyframes float3 {
        0%,
        100% {
            transform: translate(0, 0) scale(1);
            opacity: 0.3;
        }
        50% {
            transform: translate(20px, -40px) scale(1.2);
            opacity: 0.5;
        }
    }

    .grid-overlay {
        position: absolute;
        inset: 0;
        background-image: linear-gradient(
                rgba(255, 255, 255, 0.015) 1px,
                transparent 1px
            ),
            linear-gradient(
                90deg,
                rgba(255, 255, 255, 0.015) 1px,
                transparent 1px
            );
        background-size: 60px 60px;
    }

    .login-card {
        position: relative;
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(20px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 3rem;
        border-radius: 1.5rem;
        width: 100%;
        max-width: 420px;
        box-shadow:
            0 25px 50px -12px rgba(0, 0, 0, 0.5),
            0 0 0 1px rgba(6, 182, 212, 0.1);
    }

    .brand {
        text-align: center;
        margin-bottom: 2.5rem;
    }

    .logo-wrapper {
        position: relative;
        display: inline-block;
        margin-bottom: 1rem;
    }

    .logo-icon {
        width: 64px;
        height: 64px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        border-radius: 16px;
        position: relative;
        z-index: 1;
    }

    .logo-glow {
        position: absolute;
        inset: -8px;
        background: linear-gradient(
            135deg,
            rgba(6, 182, 212, 0.4),
            rgba(59, 130, 246, 0.4)
        );
        border-radius: 20px;
        filter: blur(15px);
        animation: pulse-glow 3s ease-in-out infinite;
    }

    @keyframes pulse-glow {
        0%,
        100% {
            opacity: 0.5;
            transform: scale(1);
        }
        50% {
            opacity: 0.8;
            transform: scale(1.1);
        }
    }

    h1 {
        font-size: 1.75rem;
        font-weight: 800;
        letter-spacing: -0.025em;
        color: #f1f5f9;
        margin: 0;
    }

    .subtitle {
        color: #64748b;
        font-size: 0.875rem;
        margin-top: 0.375rem;
    }

    .alert {
        padding: 0.875rem 1rem;
        border-radius: 0.75rem;
        font-size: 0.875rem;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }

    .alert-error {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: #fca5a5;
    }

    .input-group {
        margin-bottom: 1.5rem;
    }

    label {
        display: block;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #94a3b8;
        margin-bottom: 0.625rem;
    }

    input {
        width: 100%;
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 0.875rem 1rem;
        border-radius: 0.75rem;
        color: white;
        font-size: 1rem;
        transition: all 0.2s;
    }

    input:focus {
        outline: none;
        border-color: #06b6d4;
        box-shadow: 0 0 0 4px rgba(6, 182, 212, 0.15);
    }

    input::placeholder {
        color: #475569;
    }

    .btn-primary {
        width: 100%;
        background: linear-gradient(135deg, #06b6d4, #3b82f6);
        color: white;
        border: none;
        padding: 0.875rem;
        border-radius: 0.75rem;
        font-weight: 600;
        font-size: 0.9375rem;
        cursor: pointer;
        transition: all 0.3s;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
    }

    .btn-primary:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 10px 30px -10px rgba(6, 182, 212, 0.5);
    }

    .btn-primary:active:not(:disabled) {
        transform: translateY(0);
    }

    .btn-primary:disabled {
        opacity: 0.7;
        cursor: not-allowed;
    }

    .spinner {
        width: 18px;
        height: 18px;
        border: 2px solid rgba(255, 255, 255, 0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }

    .hint {
        text-align: center;
        font-size: 0.75rem;
        color: #475569;
        margin-top: 1.5rem;
    }
</style>
