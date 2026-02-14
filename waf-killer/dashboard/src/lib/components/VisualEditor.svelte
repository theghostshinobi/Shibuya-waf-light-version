<script lang="ts">
    export let config: any;

    // Initialize with empty objects to prevent errors if config is partial
    $: upstream = config.upstream || {};
    $: rules = config.rules || {};
    $: detection = config.detection || {};
    $: server = config.server || {};
    $: rateLimit = config.detection?.rate_limiting || {}; // Nested in detection
    $: ml = config.ml || {};
    $: security = config.security || {};
    $: threatIntel = config.threat_intel || {};
    $: tele = config.telemetry || {};
    $: shadow = config.shadow || {};

    // Mapping for detection mode
    let detectionModes = [
        { value: "off", label: "Off" },
        { value: "detection", label: "Detection (Log Only)" },
        { value: "blocking", label: "Blocking (Active)" },
    ];

    let logLevels = ["error", "warn", "info", "debug", "trace"];
</script>

<div class="visual-editor">
    <!-- SERVER SETTINGS -->
    <section class="card">
        <h2>🖥️ Server Settings</h2>
        <div class="form-grid">
            <label>
                HTTP Port:
                <input
                    type="number"
                    bind:value={server.http_port}
                    placeholder="8080"
                />
            </label>
            <label>
                HTTPS Port:
                <input
                    type="number"
                    bind:value={server.https_port}
                    placeholder="8443"
                />
            </label>
            <label>
                Request Timeout (s):
                <!-- Backend expects Duration string like "60s" -->
                <input
                    type="text"
                    bind:value={server.request_timeout}
                    placeholder="60s"
                />
            </label>
            <label>
                Max Connections:
                <input type="number" bind:value={server.max_connections} />
            </label>
        </div>
    </section>

    <!-- DETECTION SETTINGS -->
    <section class="card">
        <h2>🛡️ Detection Mode</h2>
        <div class="form-grid">
            <label>
                Mode:
                <select bind:value={detection.mode}>
                    {#each detectionModes as mode}
                        <option value={mode.value}>{mode.label}</option>
                    {/each}
                </select>
            </label>

            <label>
                Paranoia Level (CRS):
                <input
                    type="range"
                    bind:value={detection.crs.paranoia_level}
                    min="1"
                    max="4"
                    step="1"
                />
                <span class="value">Level {detection.crs.paranoia_level}</span>
            </label>
        </div>
    </section>

    <!-- RATE LIMITING -->
    <section class="card">
        <h2>⏱️ Rate Limiting</h2>
        <div class="form-grid">
            <label>
                <input type="checkbox" bind:checked={rateLimit.enabled} />
                Enable Rate Limiting
            </label>
            <label>
                Requests / Second:
                <input
                    type="number"
                    bind:value={rateLimit.requests_per_second}
                    disabled={!rateLimit.enabled}
                />
            </label>
            <label>
                Burst Size:
                <input
                    type="number"
                    bind:value={rateLimit.burst_size}
                    disabled={!rateLimit.enabled}
                />
            </label>
            <label>
                Ban Duration (seconds):
                <input
                    type="number"
                    bind:value={rateLimit.ban_duration_secs}
                    disabled={!rateLimit.enabled}
                />
            </label>
        </div>
    </section>

    <!-- BACKEND SECTION -->
    <section class="card">
        <h2>🔗 Backend (Upstream)</h2>
        <div class="form-grid">
            <label>
                Backend URL:
                <input
                    type="text"
                    bind:value={upstream.backend_url}
                    placeholder="http://localhost:3000"
                />
            </label>

            <label>
                Connect Timeout:
                <input
                    type="text"
                    bind:value={upstream.connect_timeout}
                    placeholder="5s"
                />
            </label>
            <label>
                Pool Size:
                <input type="number" bind:value={upstream.pool_size} />
            </label>
        </div>
    </section>

    <!-- RULES SECTION -->
    <section class="card">
        <h2>⚡ Rules & Thresholds</h2>
        <div class="form-grid">
            <label>
                Inbound Anomaly Threshold:
                <input
                    type="number"
                    bind:value={detection.crs.inbound_threshold}
                    min="1"
                    max="100"
                />
            </label>

            <label>
                Outbound Anomaly Threshold:
                <input
                    type="number"
                    bind:value={detection.crs.outbound_threshold}
                    min="1"
                    max="100"
                />
            </label>
        </div>
    </section>

    <!-- ML SECTION -->
    <section class="card">
        <h2>🤖 ML Anomaly Detection</h2>
        <div class="form-grid">
            <label>
                <input type="checkbox" bind:checked={ml.enabled} />
                Enable ML Detection
            </label>

            <label>
                Anomaly Threshold:
                <input
                    type="range"
                    bind:value={ml.threshold}
                    min="0"
                    max="1"
                    step="0.05"
                    disabled={!ml.enabled}
                />
                <span class="value">{ml.threshold?.toFixed(2) || "0.70"}</span>
            </label>
            <label>
                ML Weight:
                <input
                    type="range"
                    bind:value={ml.ml_weight}
                    min="0"
                    max="1"
                    step="0.1"
                    disabled={!ml.enabled}
                />
                <span class="value">{ml.ml_weight?.toFixed(1) || "0.3"}</span>
            </label>

            <label>
                Shadow Mode (Log Only):
                <input
                    type="checkbox"
                    bind:checked={ml.shadow_mode}
                    disabled={!ml.enabled}
                />
            </label>
        </div>
    </section>

    <!-- SECURITY LIMITS -->
    <section class="card">
        <h2>🚫 Security Limits</h2>
        <div class="form-grid">
            <label>
                Max Body Size (bytes):
                <input type="number" bind:value={security.max_body_size} />
            </label>
            <label>
                Max URI Length:
                <input type="number" bind:value={security.max_uri_length} />
            </label>
        </div>
    </section>

    <!-- THREAT INTEL -->
    <section class="card">
        <h2>🌐 Threat Intelligence</h2>
        <div class="form-grid">
            <label>
                <input type="checkbox" bind:checked={threatIntel.enabled} />
                Enable Threat Intel
            </label>

            <label>
                Score Threshold:
                <input
                    type="range"
                    bind:value={threatIntel.score_threshold}
                    min="0"
                    max="100"
                    step="5"
                    disabled={!threatIntel.enabled}
                />
                <span class="value">{threatIntel.score_threshold}</span>
            </label>
            <label>
                Cache TTL (Hours):
                <input
                    type="number"
                    bind:value={threatIntel.cache_ttl_hours}
                    disabled={!threatIntel.enabled}
                />
            </label>
        </div>
    </section>

    <!-- GLOBAL SHADOW MODE -->
    <section class="card">
        <h2>👻 Global Shadow Mode</h2>
        <div class="form-grid">
            <label>
                <input type="checkbox" bind:checked={shadow.enabled} />
                Enable Shadow Mode (Traffic Replay)
            </label>

            <label>
                Traffic Percentage:
                <input
                    type="range"
                    bind:value={shadow.percentage}
                    min="1"
                    max="100"
                    step="1"
                    disabled={!shadow.enabled}
                />
                <span class="value">{shadow.percentage}%</span>
            </label>
        </div>
    </section>

    <!-- TELEMETRY -->
    <section class="card">
        <h2>📊 Telemetry & Logging</h2>
        <div class="form-grid">
            <label>
                Log Level:
                <select bind:value={tele.log_level}>
                    {#each logLevels as level}
                        <option value={level}>{level.toUpperCase()}</option>
                    {/each}
                </select>
            </label>
            <label>
                <input type="checkbox" bind:checked={tele.metrics_enabled} />
                Enable Prometheus Metrics
            </label>
            <label>
                Metrics Port:
                <input
                    type="number"
                    bind:value={tele.metrics_port}
                    disabled={!tele.metrics_enabled}
                />
            </label>
        </div>
    </section>
</div>

<style>
    .visual-editor {
        padding: 2rem;
        background: #f5f5f5;
        max-height: 70vh;
        overflow-y: auto;
    }

    .card {
        background: white;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    .card h2 {
        margin: 0 0 1rem 0;
        font-size: 1.25rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }

    .form-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 1.5rem;
    }

    label {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        font-size: 0.9rem;
        color: #555;
    }

    input[type="text"],
    input[type="number"],
    select {
        padding: 0.5rem;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1rem;
    }

    input[type="range"] {
        width: 100%;
    }

    .value {
        font-weight: bold;
        color: #007bff;
        align-self: flex-end;
    }
</style>
