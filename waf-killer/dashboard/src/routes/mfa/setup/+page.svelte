<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import { goto } from "$app/navigation";

    let qrCodeSvg = "";
    let secret = "";
    let code = "";
    let error = "";
    let verifying = false;

    onMount(async () => {
        try {
            const setup = await api.getMFASetup();
            qrCodeSvg = setup.qr_code;
            secret = setup.secret;
        } catch (e: any) {
            error = "Failed to load MFA setup: " + e.message;
        }
    });

    async function handleVerify() {
        verifying = true;
        error = "";
        try {
            // In a real app, first verification is special to "activate" MFA
            await api.verifyMFA("initial-setup", code);
            goto("/settings/security?mfa=enabled");
        } catch (e: any) {
            error = "Invalid code. Please try again.";
        } finally {
            verifying = false;
        }
    }
</script>

<div class="mfa-setup">
    <h1>Secure Your Account</h1>
    <p class="description">
        Scan the QR code below with your authenticator app (e.g., Google
        Authenticator, Authy) to enable Two-Factor Authentication.
    </p>

    {#if error}
        <div class="alert alert-error">{error}</div>
    {/if}

    <div class="setup-container">
        <div class="qr-code">
            {@html qrCodeSvg}
        </div>

        <div class="manual-entry">
            <label>Manual Entry Key</label>
            <code>{secret}</code>
        </div>

        <div class="verification-form">
            <h3>Enter verification code</h3>
            <p>Enter the 6-digit code from your app to confirm setup.</p>

            <form on:submit|preventDefault={handleVerify}>
                <input
                    type="text"
                    placeholder="000000"
                    bind:value={code}
                    maxlength="6"
                    required
                />
                <button type="submit" disabled={verifying}>
                    {verifying ? "Verifying..." : "Verify and Enable"}
                </button>
            </form>
        </div>
    </div>
</div>

<style>
    .mfa-setup {
        max-width: 600px;
        margin: 4rem auto;
        padding: 2rem;
        background: #1e293b;
        border-radius: 1rem;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
    }

    h1 {
        font-size: 1.5rem;
        margin-bottom: 1rem;
    }
    .description {
        color: #94a3b8;
        line-height: 1.6;
        margin-bottom: 2rem;
    }

    .setup-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2rem;
    }

    .qr-code {
        background: white;
        padding: 1rem;
        border-radius: 0.5rem;
    }

    .manual-entry {
        text-align: center;
        width: 100%;
    }

    .manual-entry label {
        display: block;
        font-size: 0.75rem;
        text-transform: uppercase;
        color: #475569;
        margin-bottom: 0.5rem;
    }

    code {
        display: block;
        background: #0f172a;
        padding: 0.75rem;
        border-radius: 0.5rem;
        letter-spacing: 0.1em;
        font-family: monospace;
    }

    .verification-form {
        width: 100%;
        border-top: 1px solid #334155;
        padding-top: 2rem;
        text-align: center;
    }

    .verification-form h3 {
        margin-bottom: 0.5rem;
    }
    .verification-form p {
        color: #64748b;
        font-size: 0.875rem;
        margin-bottom: 1.5rem;
    }

    form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
        max-width: 300px;
        margin: 0 auto;
    }

    input {
        background: #0f172a;
        border: 1px solid #334155;
        padding: 0.75rem;
        border-radius: 0.5rem;
        color: white;
        text-align: center;
        font-size: 1.25rem;
        letter-spacing: 0.2em;
    }

    button {
        background: #3b82f6;
        color: white;
        border: none;
        padding: 0.75rem;
        border-radius: 0.5rem;
        font-weight: 600;
        cursor: pointer;
    }

    button:hover {
        background: #2563eb;
    }
    button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }

    .alert-error {
        background: rgba(239, 68, 68, 0.1);
        color: #f87171;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 2rem;
    }
</style>
