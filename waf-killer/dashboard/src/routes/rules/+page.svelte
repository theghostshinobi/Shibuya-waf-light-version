<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    import type { RuleInfo } from "$lib/types";
    import {
        Shield,
        ShieldCheck,
        ShieldAlert,
        ShieldX,
        Check,
        X,
        Zap,
        AlertTriangle,
        Bug,
        Code,
        Database,
        FileCode,
        Globe,
        Lock,
        Terminal,
        Skull,
        Eye,
        Search,
        RefreshCw,
        Loader,
        Trash2,
    } from "lucide-svelte";
    import { fly, fade } from "svelte/transition";

    interface OwaspRule {
        id: string;
        name: string;
        category: string;
        owasp: string;
        severity: "critical" | "high" | "medium";
        description: string;
        pattern: string;
        enabled: boolean;
        backendId: string | null;
        tags: string[];
    }

    const OWASP_RULES: OwaspRule[] = [
        // --- CRITICAL ---
        {
            id: "SQLI-UNION",
            name: "SQL Injection — Union Based",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects UNION-based SQL injection attempts that extract data by combining queries",
            pattern: "(?i)union\\s+(all\\s+)?select\\s+",
            enabled: true,
            backendId: null,
            tags: ["sqli", "union", "data-extraction"],
        },
        {
            id: "SQLI-BOOLEAN",
            name: "SQL Injection — Boolean Blind",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects boolean-based blind SQL injection using OR/AND true conditions",
            pattern:
                "(?i)(\\b(or|and)\\b\\s+['\"]?\\d+['\"]?\\s*[=<>]|\\b(or|and)\\b\\s+['\"]\\w+['\"]\\s*=\\s*['\"]\\w+['\"])",
            enabled: true,
            backendId: null,
            tags: ["sqli", "blind", "boolean"],
        },
        {
            id: "SQLI-TIME",
            name: "SQL Injection — Time-Based Blind",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects time-based blind SQL injection using SLEEP, BENCHMARK, WAITFOR DELAY",
            pattern:
                "(?i)(sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay|pg_sleep)",
            enabled: true,
            backendId: null,
            tags: ["sqli", "time-based", "blind"],
        },
        {
            id: "XSS-REFLECTED",
            name: "Cross-Site Scripting — Reflected",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects reflected XSS via script tags, javascript: URIs, and event handlers",
            pattern:
                "(?i)(<script[^>]*>|javascript\\s*:|on(load|error|click|mouseover|focus|blur|submit)\\s*=)",
            enabled: true,
            backendId: null,
            tags: ["xss", "reflected", "script-injection"],
        },
        {
            id: "XSS-DOM",
            name: "Cross-Site Scripting — Stored/DOM",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects DOM-based and stored XSS patterns including innerHTML, document.write, eval",
            pattern:
                "(?i)(document\\.(write|cookie|domain)|innerHTML|outerHTML|eval\\s*\\(|setTimeout\\s*\\(|setInterval\\s*\\()",
            enabled: true,
            backendId: null,
            tags: ["xss", "dom", "stored"],
        },
        {
            id: "XSS-EVENT",
            name: "XSS via Event Handlers",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects XSS attempts using HTML event handler attributes like onerror, onfocus, onload",
            pattern:
                "(?i)\\bon(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload)\\s*=",
            enabled: true,
            backendId: null,
            tags: ["xss", "event-handler", "html"],
        },
        {
            id: "XXE",
            name: "XML External Entity (XXE)",
            category: "Injection",
            owasp: "A05:2021",
            severity: "critical",
            description:
                "Detects XXE attacks using DOCTYPE declarations with ENTITY definitions and SYSTEM/PUBLIC keywords",
            pattern:
                "(?i)(<!DOCTYPE[^>]*\\[|<!ENTITY|SYSTEM\\s+['\"]|PUBLIC\\s+['\"]|<\\?xml.*encoding)",
            enabled: true,
            backendId: null,
            tags: ["xxe", "xml", "entity"],
        },
        {
            id: "RCE-CMD",
            name: "Remote Code Execution — OS Command",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects OS command injection via shell metacharacters, pipes, backticks, and command chaining",
            pattern:
                "(?i)(;\\s*(ls|cat|id|whoami|uname|pwd|wget|curl)|\\|\\s*(ls|cat|id|whoami)|`[^`]*`|\\$\\(|\\b(eval|exec|system|passthru|popen|proc_open|shell_exec)\\s*\\()",
            enabled: true,
            backendId: null,
            tags: ["rce", "os-command", "shell"],
        },
        {
            id: "RCE-CODE",
            name: "Remote Code Execution — Code Injection",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects server-side code injection attempts targeting PHP, Python, Node.js, and Ruby",
            pattern:
                "(?i)(\\bimport\\s+os\\b|\\b__import__\\b|require\\s*\\(|child_process|\\bProcess\\.start|Runtime\\.getRuntime)",
            enabled: true,
            backendId: null,
            tags: ["rce", "code-injection", "server-side"],
        },
        {
            id: "DESER",
            name: "Deserialization Attack",
            category: "Injection",
            owasp: "A08:2021",
            severity: "critical",
            description:
                "Detects unsafe deserialization payloads in Java, PHP, Python, and .NET",
            pattern:
                '(?i)(O:\\d+:"|rO0ABX|aced0005|\\bpickle\\.(loads|load)|yaml\\.unsafe_load|ObjectInputStream|BinaryFormatter)',
            enabled: true,
            backendId: null,
            tags: ["deserialization", "java", "php"],
        },
        {
            id: "LOG4SHELL",
            name: "Log4Shell / JNDI Injection",
            category: "Injection",
            owasp: "A06:2021",
            severity: "critical",
            description:
                "Detects Log4j/Log4Shell JNDI lookup injection patterns (CVE-2021-44228)",
            pattern:
                "(?i)(\\$\\{.*j.*n.*d.*i.*:|\\$\\{jndi:(ldap|rmi|dns|ldaps|iiop)://|\\$\\{\\$\\{.*lower.*:|\\$\\{env:|\\$\\{sys:)",
            enabled: true,
            backendId: null,
            tags: ["log4shell", "jndi", "cve-2021-44228"],
        },
        {
            id: "LFI",
            name: "Local File Inclusion (LFI)",
            category: "Path Traversal",
            owasp: "A01:2021",
            severity: "critical",
            description:
                "Detects local file inclusion via path traversal, /etc/passwd, /proc access, and null bytes",
            pattern:
                "(?i)(\\.\\./|\\.\\.\\\\|/etc/(passwd|shadow|hosts)|/proc/(self|version)|%00|%2e%2e)",
            enabled: true,
            backendId: null,
            tags: ["lfi", "path-traversal", "file-read"],
        },
        {
            id: "RFI",
            name: "Remote File Inclusion (RFI)",
            category: "Path Traversal",
            owasp: "A01:2021",
            severity: "critical",
            description:
                "Detects remote file inclusion attempts via external URL loading in parameters",
            pattern:
                "(?i)(=(https?|ftp|php|data|expect|input)://|=(\\\\\\\\|//)\\w+)",
            enabled: true,
            backendId: null,
            tags: ["rfi", "remote-include", "url-injection"],
        },
        {
            id: "SSTI",
            name: "Server-Side Template Injection (SSTI)",
            category: "Injection",
            owasp: "A03:2021",
            severity: "critical",
            description:
                "Detects SSTI payloads targeting Jinja2, Twig, Freemarker, Velocity, and Mako",
            pattern:
                "(?i)(\\{\\{.*\\}\\}|\\{%.*%\\}|\\$\\{.*\\}|#\\{.*\\}|<%.*%>|<#.*>|\\[\\[.*\\]\\])",
            enabled: true,
            backendId: null,
            tags: ["ssti", "template", "jinja2"],
        },
        {
            id: "SMUGGLE",
            name: "HTTP Request Smuggling",
            category: "Protocol",
            owasp: "A05:2021",
            severity: "critical",
            description:
                "Detects HTTP request smuggling via conflicting Content-Length and Transfer-Encoding headers",
            pattern:
                "(?i)(transfer-encoding\\s*:\\s*chunked.*content-length|content-length.*transfer-encoding\\s*:\\s*chunked|\\r\\n\\r\\n.*\\r\\n)",
            enabled: true,
            backendId: null,
            tags: ["smuggling", "http", "desync"],
        },
        {
            id: "SHELLSHOCK",
            name: "Shellshock (CVE-2014-6271)",
            category: "Injection",
            owasp: "A06:2021",
            severity: "critical",
            description:
                "Detects Bash Shellshock vulnerability exploitation via environment variable injection",
            pattern: "(?i)(\\(\\)\\s*\\{.*};|\\{\\s*:;\\s*\\};|%28%29%20%7B)",
            enabled: true,
            backendId: null,
            tags: ["shellshock", "bash", "cve-2014-6271"],
        },
        {
            id: "WEBSHELL",
            name: "Web Shell Detection",
            category: "Malware",
            owasp: "A05:2021",
            severity: "critical",
            description:
                "Detects known web shell signatures including c99, r57, WSO, and common backdoor patterns",
            pattern:
                "(?i)(c99shell|r57shell|webshell|WSO\\s|b374k|FilesMan|\\bpassthru\\b|\\bsystem\\b.*\\$_(GET|POST|REQUEST))",
            enabled: true,
            backendId: null,
            tags: ["webshell", "backdoor", "malware"],
        },
        // --- HIGH ---
        {
            id: "SSRF",
            name: "Server-Side Request Forgery (SSRF)",
            category: "SSRF",
            owasp: "A10:2021",
            severity: "high",
            description:
                "Detects SSRF via internal IP ranges, cloud metadata endpoints, and localhost access",
            pattern:
                "(?i)(169\\.254\\.169\\.254|127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|\\[::1\\]|metadata\\.google|100\\.100\\.100\\.200|instance-data)",
            enabled: true,
            backendId: null,
            tags: ["ssrf", "internal", "metadata"],
        },
        {
            id: "PATH-TRAV",
            name: "Path Traversal",
            category: "Path Traversal",
            owasp: "A01:2021",
            severity: "high",
            description:
                "Detects directory traversal attempts using encoded sequences and double-encoding",
            pattern:
                "(?i)(%2e%2e%2f|%252e%252e%252f|\\.%2e/|%2e\\./|\\.\\.%5c|%5c\\.\\.|\\.\\.%255c)",
            enabled: true,
            backendId: null,
            tags: ["path-traversal", "directory", "encoding"],
        },
        {
            id: "LDAP",
            name: "LDAP Injection",
            category: "Injection",
            owasp: "A03:2021",
            severity: "high",
            description:
                "Detects LDAP injection via special characters and filter manipulation",
            pattern:
                "(?i)(\\(\\|\\(|\\(\\&\\(|\\)\\(\\||\\)\\(\\&|\\*\\)\\(|\\)\\(cn=|\\)\\(uid=|\\)\\(objectClass=)",
            enabled: true,
            backendId: null,
            tags: ["ldap", "injection", "directory-service"],
        },
        {
            id: "NOSQL",
            name: "NoSQL Injection",
            category: "Injection",
            owasp: "A03:2021",
            severity: "high",
            description:
                "Detects NoSQL injection targeting MongoDB operators ($gt, $ne, $where, $regex)",
            pattern:
                "(?i)(\\$(?:gt|gte|lt|lte|ne|nin|in|exists|where|regex|or|and|not|nor|elemMatch)\\b|\\{\\s*['\"]\\$)",
            enabled: true,
            backendId: null,
            tags: ["nosql", "mongodb", "injection"],
        },
        {
            id: "CRLF",
            name: "CRLF Injection / HTTP Response Splitting",
            category: "Injection",
            owasp: "A03:2021",
            severity: "high",
            description:
                "Detects CRLF injection in HTTP headers to perform response splitting attacks",
            pattern: "(%0d%0a|%0d|%0a|\\r\\n|%5cr%5cn|%E5%98%8A%E5%98%8D)",
            enabled: true,
            backendId: null,
            tags: ["crlf", "header-injection", "response-splitting"],
        },
        {
            id: "PHP-OBJ",
            name: "PHP Object Injection",
            category: "Injection",
            owasp: "A08:2021",
            severity: "high",
            description:
                "Detects PHP object injection via serialized data and magic method exploitation",
            pattern:
                '(?i)(O:\\d+:"[A-Za-z_]+":\\d+:\\{|a:\\d+:\\{|s:\\d+:"[^"]+";)',
            enabled: true,
            backendId: null,
            tags: ["php", "object-injection", "serialization"],
        },
        {
            id: "SESSION-FIX",
            name: "Session Fixation",
            category: "Auth",
            owasp: "A07:2021",
            severity: "high",
            description:
                "Detects session fixation attacks via session ID injection in URLs and cookies",
            pattern:
                "(?i)(PHPSESSID|JSESSIONID|ASPSESSIONID|sid)\\s*=\\s*[a-f0-9]{16,}",
            enabled: true,
            backendId: null,
            tags: ["session", "fixation", "auth-bypass"],
        },
        {
            id: "DATA-LEAK",
            name: "Sensitive Data Exposure (Response)",
            category: "Data",
            owasp: "A02:2021",
            severity: "high",
            description:
                "Detects potential sensitive data leaks including credit card numbers, SSNs, and API keys in responses",
            pattern:
                "(?i)(\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b|\\b\\d{3}-\\d{2}-\\d{4}\\b|password\\s*[:=]|api[_-]?key\\s*[:=])",
            enabled: true,
            backendId: null,
            tags: ["data-leak", "pii", "response"],
        },
        // --- MEDIUM ---
        {
            id: "CORS",
            name: "CORS Misconfiguration Exploit",
            category: "Config",
            owasp: "A05:2021",
            severity: "medium",
            description:
                "Detects attempts to exploit CORS misconfigurations via null origin or wildcard abuse",
            pattern:
                "(?i)(origin:\\s*null|origin:\\s*https?://evil|access-control-allow-origin:\\s*\\*)",
            enabled: true,
            backendId: null,
            tags: ["cors", "origin", "misconfiguration"],
        },
        {
            id: "REDIRECT",
            name: "Open Redirect",
            category: "Redirect",
            owasp: "A01:2021",
            severity: "medium",
            description:
                "Detects open redirect attempts via URL parameters pointing to external domains",
            pattern:
                "(?i)(=\\s*https?%3a%2f%2f|=(https?:)?//[^/]|redirect(.*?)=|url=|next=|return(.*?)=|goto=)(https?://|//)",
            enabled: true,
            backendId: null,
            tags: ["redirect", "phishing", "url"],
        },
        {
            id: "SCANNER",
            name: "Security Scanner / Bot Detection",
            category: "Recon",
            owasp: "A07:2021",
            severity: "medium",
            description:
                "Detects automated security scanners like Nikto, SQLMap, Nmap, DirBuster, and Burp Suite",
            pattern:
                "(?i)(nikto|sqlmap|nmap|dirbuster|burpsuite|masscan|zgrab|gobuster|wfuzz|hydra|metasploit|w3af)",
            enabled: true,
            backendId: null,
            tags: ["scanner", "bot", "recon"],
        },
        {
            id: "PROTO-VIOL",
            name: "HTTP Protocol Violation",
            category: "Protocol",
            owasp: "A05:2021",
            severity: "medium",
            description:
                "Detects HTTP protocol violations including malformed headers and illegal methods",
            pattern:
                "(?i)(TRACE|TRACK|CONNECT|DEBUG|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\\s+/",
            enabled: true,
            backendId: null,
            tags: ["protocol", "http", "method"],
        },
        {
            id: "BRUTE",
            name: "Rate Limiting / Brute Force Protection",
            category: "Auth",
            owasp: "A07:2021",
            severity: "medium",
            description:
                "Monitors for brute force patterns on login endpoints and rate limit violations",
            pattern:
                "(?i)(/login|/signin|/auth|/api/token|/oauth/token|/wp-login)",
            enabled: true,
            backendId: null,
            tags: ["brute-force", "rate-limit", "auth"],
        },
    ];

    let rules: OwaspRule[] = [...OWASP_RULES];
    let legacyRules: RuleInfo[] = [];
    let loading2 = true;
    let seedingRules = false;
    let cleaningUp = false;
    let reloading = false;
    let showToast = false;
    let toastMessage = "";
    let toastType: "success" | "error" = "success";
    let filterSeverity = "all";
    let searchQuery = "";

    onMount(async () => {
        await syncWithBackend();
    });

    async function syncWithBackend() {
        loading2 = true;
        try {
            const backendRules: RuleInfo[] = await api.getRules();
            const owaspNames = rules.map((r) => r.name);
            // Map backend rules to our OWASP categories
            for (const owaspRule of rules) {
                const match = backendRules.find(
                    (br) =>
                        br.description?.includes(owaspRule.name) ||
                        br.id === owaspRule.backendId,
                );
                if (match) {
                    owaspRule.backendId = match.id;
                    owaspRule.enabled = match.enabled;
                }
            }
            // Collect legacy/junk rules not matching any OWASP rule
            legacyRules = backendRules.filter((br) => {
                return !rules.some(
                    (r) =>
                        r.backendId === br.id ||
                        br.description?.includes(r.name),
                );
            });
        } catch (e) {
            console.warn(
                "Could not sync with backend rules, using defaults",
                e,
            );
        } finally {
            loading2 = false;
        }
    }

    async function toggleRule(rule: OwaspRule) {
        const newState = !rule.enabled;
        rule.enabled = newState;
        rules = [...rules]; // trigger reactivity

        if (rule.backendId) {
            try {
                await api.updateRule(rule.backendId, {
                    enabled: newState,
                });
                notify(
                    `${rule.name} ${newState ? "enabled" : "disabled"}`,
                    "success",
                );
            } catch (e) {
                rule.enabled = !newState;
                rules = [...rules];
                notify(`Failed to toggle ${rule.name}`, "error");
            }
        } else {
            // Create rule in backend if it doesn't exist yet
            try {
                const result = await api.createRule({
                    name: rule.name,
                    pattern: rule.pattern,
                    risk_score:
                        rule.severity === "critical"
                            ? 9
                            : rule.severity === "high"
                              ? 7
                              : 5,
                    action: "BLOCK",
                    description: rule.name,
                });
                rule.backendId = result.id;
                rules = [...rules];
                notify(`${rule.name} created and enabled`, "success");
            } catch (e) {
                rule.enabled = !newState;
                rules = [...rules];
                notify(`Failed to create ${rule.name}`, "error");
            }
        }
    }

    async function seedAllRules() {
        seedingRules = true;
        let created = 0;
        for (const rule of rules) {
            if (!rule.backendId) {
                try {
                    const result = await api.createRule({
                        name: rule.name,
                        pattern: rule.pattern,
                        risk_score:
                            rule.severity === "critical"
                                ? 9
                                : rule.severity === "high"
                                  ? 7
                                  : 5,
                        action: "BLOCK",
                        description: rule.name,
                    });
                    rule.backendId = result.id;
                    created++;
                } catch {
                    /* skip */
                }
            }
        }
        rules = [...rules];
        seedingRules = false;
        if (created > 0) {
            notify(`Deployed ${created} OWASP rules to WAF engine`, "success");
        } else {
            notify("All rules already deployed", "success");
        }
    }

    async function deleteOwasp(rule: OwaspRule) {
        if (!rule.backendId) {
            notify("Rule not deployed — nothing to delete", "error");
            return;
        }
        try {
            await api.deleteRule(rule.backendId);
            rule.backendId = null;
            rule.enabled = true;
            rules = [...rules];
            notify(`${rule.name} deleted from WAF`, "success");
        } catch (e: any) {
            notify(`Failed to delete rule: ${e.message}`, "error");
        }
    }

    async function deleteLegacyRule(rule: RuleInfo) {
        try {
            await api.deleteRule(rule.id);
            legacyRules = legacyRules.filter((r) => r.id !== rule.id);
            notify(`Deleted legacy rule ${rule.id}`, "success");
        } catch (e: any) {
            notify(`Failed to delete: ${e.message}`, "error");
        }
    }

    async function deleteAllLegacy() {
        if (
            !confirm(
                `Delete all ${legacyRules.length} legacy CRS rules? This cannot be undone.`,
            )
        )
            return;
        cleaningUp = true;
        let deleted = 0;
        for (const rule of [...legacyRules]) {
            try {
                await api.deleteRule(rule.id);
                deleted++;
            } catch {
                /* skip */
            }
        }
        legacyRules = [];
        cleaningUp = false;
        notify(`Cleaned up ${deleted} legacy rules`, "success");
    }

    async function reloadCRSRules() {
        reloading = true;
        try {
            const res = await api.reloadRules();
            if (res.success) {
                notify(
                    `Reloaded ${res.rules_loaded} CRS rules from disk`,
                    "success",
                );
                await syncWithBackend();
            } else {
                notify(res.message || "Reload failed", "error");
            }
        } catch (e: any) {
            notify(`Reload failed: ${e.message}`, "error");
        } finally {
            reloading = false;
        }
    }

    function notify(msg: string, type: "success" | "error") {
        toastMessage = msg;
        toastType = type;
        showToast = true;
        setTimeout(() => {
            showToast = false;
        }, 2500);
    }

    function getSeverityColor(s: string): string {
        switch (s) {
            case "critical":
                return "#ef4444";
            case "high":
                return "#f59e0b";
            case "medium":
                return "#3b82f6";
            default:
                return "#888";
        }
    }

    function getCategoryIcon(cat: string): typeof Shield {
        switch (cat) {
            case "Injection":
                return Code;
            case "Path Traversal":
                return FileCode;
            case "SSRF":
                return Globe;
            case "Protocol":
                return AlertTriangle;
            case "Auth":
                return Lock;
            case "Data":
                return Database;
            case "Config":
                return Shield;
            case "Redirect":
                return Globe;
            case "Recon":
                return Search;
            case "Malware":
                return Skull;
            default:
                return Shield;
        }
    }

    $: filteredRules = rules.filter((r) => {
        if (filterSeverity !== "all" && r.severity !== filterSeverity)
            return false;
        if (searchQuery) {
            const q = searchQuery.toLowerCase();
            return (
                r.name.toLowerCase().includes(q) ||
                r.description.toLowerCase().includes(q) ||
                r.category.toLowerCase().includes(q) ||
                r.owasp.toLowerCase().includes(q) ||
                r.tags.some((t) => t.includes(q))
            );
        }
        return true;
    });

    $: criticalCount = rules.filter((r) => r.severity === "critical").length;
    $: highCount = rules.filter((r) => r.severity === "high").length;
    $: mediumCount = rules.filter((r) => r.severity === "medium").length;
    $: enabledCount = rules.filter((r) => r.enabled).length;
</script>

<div class="page">
    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <div class="title-row">
                <div class="icon-circle">
                    <ShieldCheck size={24} />
                </div>
                <div>
                    <h1>Rules Engine</h1>
                    <p class="subtitle">
                        OWASP Top 30 Attack Detection Rules — Real-Time WAF
                        Protection
                    </p>
                </div>
            </div>
        </div>
        <div class="header-actions">
            <button
                class="btn-reload"
                on:click={reloadCRSRules}
                disabled={reloading}
            >
                {#if reloading}
                    <Loader size={16} class="spin" />
                    Reloading...
                {:else}
                    <RefreshCw size={16} />
                    Reload CRS Rules
                {/if}
            </button>
            <button
                class="btn-deploy"
                on:click={seedAllRules}
                disabled={seedingRules}
            >
                {#if seedingRules}
                    <Loader size={16} class="spin" />
                    Deploying...
                {:else}
                    <Zap size={16} />
                    Deploy All to WAF
                {/if}
            </button>
        </div>
    </div>

    <!-- Stats Bar -->
    <div class="stats-bar">
        <div class="stat-pill">
            <span class="pill-dot critical"></span>
            <span class="pill-label">{criticalCount} Critical</span>
        </div>
        <div class="stat-pill">
            <span class="pill-dot high"></span>
            <span class="pill-label">{highCount} High</span>
        </div>
        <div class="stat-pill">
            <span class="pill-dot medium"></span>
            <span class="pill-label">{mediumCount} Medium</span>
        </div>
        <div class="divider"></div>
        <div class="stat-pill active">
            <ShieldCheck size={14} />
            <span class="pill-label">{enabledCount}/{rules.length} Active</span>
        </div>
    </div>

    <!-- Filters -->
    <div class="filters">
        <div class="search-box">
            <Search size={16} />
            <input
                type="text"
                placeholder="Search rules..."
                bind:value={searchQuery}
            />
        </div>
        <div class="filter-tabs">
            <button
                class:active={filterSeverity === "all"}
                on:click={() => (filterSeverity = "all")}>All</button
            >
            <button
                class:active={filterSeverity === "critical"}
                on:click={() => (filterSeverity = "critical")}
            >
                <span class="pill-dot critical small"></span> Critical
            </button>
            <button
                class:active={filterSeverity === "high"}
                on:click={() => (filterSeverity = "high")}
            >
                <span class="pill-dot high small"></span> High
            </button>
            <button
                class:active={filterSeverity === "medium"}
                on:click={() => (filterSeverity = "medium")}
            >
                <span class="pill-dot medium small"></span> Medium
            </button>
        </div>
    </div>

    <!-- Rules List -->
    <div class="rules-list">
        {#each filteredRules as rule (rule.id)}
            <div
                class="rule-card"
                class:disabled={!rule.enabled}
                transition:fly={{ y: 10, duration: 200 }}
            >
                <div class="rule-left">
                    <div
                        class="rule-icon"
                        style="color: {getSeverityColor(rule.severity)}"
                    >
                        <svelte:component
                            this={getCategoryIcon(rule.category)}
                            size={18}
                        />
                    </div>
                    <div class="rule-info">
                        <div class="rule-name-row">
                            <span class="rule-name">{rule.name}</span>
                            <span class="owasp-badge">{rule.owasp}</span>
                            <span class="severity-badge {rule.severity}"
                                >{rule.severity}</span
                            >
                        </div>
                        <p class="rule-desc">{rule.description}</p>
                        <div class="rule-meta">
                            <code class="pattern-preview"
                                >{rule.pattern.length > 80
                                    ? rule.pattern.slice(0, 80) + "..."
                                    : rule.pattern}</code
                            >
                            <div class="rule-tags">
                                {#each rule.tags as tag}
                                    <span class="tag">{tag}</span>
                                {/each}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="rule-right">
                    {#if rule.backendId}
                        <span class="deployed-badge">Deployed</span>
                        <button
                            class="btn-delete"
                            on:click={() => deleteOwasp(rule)}
                            title="Delete from WAF"
                        >
                            <Trash2 size={14} />
                        </button>
                    {/if}
                    <button
                        class="rule-toggle"
                        class:on={rule.enabled}
                        on:click={() => toggleRule(rule)}
                    >
                        <span class="toggle-knob"></span>
                    </button>
                </div>
            </div>
        {/each}
    </div>

    {#if filteredRules.length === 0}
        <div class="empty-state">
            <Search size={32} />
            <p>No rules match your filters</p>
        </div>
    {/if}

    <!-- Legacy Rules Cleanup -->
    {#if legacyRules.length > 0}
        <div class="legacy-section">
            <div class="legacy-header">
                <div>
                    <h3>Legacy CRS Rules</h3>
                    <p class="legacy-desc">
                        {legacyRules.length} old rules loaded from CRS config files
                        — these can be safely removed
                    </p>
                </div>
                <button
                    class="btn-cleanup"
                    on:click={deleteAllLegacy}
                    disabled={cleaningUp}
                >
                    <Trash2 size={14} />
                    {cleaningUp ? "Cleaning..." : "Delete All Legacy"}
                </button>
            </div>
            <div class="legacy-list">
                {#each legacyRules.slice(0, 20) as rule}
                    <div class="legacy-item">
                        <span class="legacy-id">{rule.id}</span>
                        <span class="legacy-name"
                            >{rule.description || "No description"}</span
                        >
                        <button
                            class="btn-delete-sm"
                            on:click={() => deleteLegacyRule(rule)}
                        >
                            <Trash2 size={12} />
                        </button>
                    </div>
                {/each}
                {#if legacyRules.length > 20}
                    <div class="legacy-more">
                        ...and {legacyRules.length - 20} more
                    </div>
                {/if}
            </div>
        </div>
    {/if}
</div>

<!-- Toast -->
{#if showToast}
    <div class="toast {toastType}" transition:fly={{ y: 50, duration: 300 }}>
        {#if toastType === "success"}
            <Check size={16} />
        {:else}
            <AlertTriangle size={16} />
        {/if}
        <span>{toastMessage}</span>
    </div>
{/if}

<style>
    .page {
        max-width: 1100px;
        margin: 0 auto;
        padding: 2rem 1.5rem;
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
    }

    /* Header */
    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
    }
    .title-row {
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .icon-circle {
        width: 48px;
        height: 48px;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, #10b981, #059669);
        color: white;
    }
    h1 {
        font-size: 1.75rem;
        font-weight: 800;
        color: white;
        margin: 0;
    }
    .subtitle {
        color: #666;
        margin: 0.25rem 0 0;
        font-size: 0.875rem;
    }
    .btn-reload {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.6rem 1.25rem;
        border-radius: 10px;
        border: 1px solid #3b82f6;
        background: rgba(59, 130, 246, 0.1);
        color: #60a5fa;
        font-weight: 600;
        font-size: 0.8125rem;
        cursor: pointer;
        transition: all 0.2s;
    }
    .btn-reload:hover {
        background: rgba(59, 130, 246, 0.2);
        transform: translateY(-1px);
    }
    .btn-reload:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
    }

    .btn-deploy {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.6rem 1.25rem;
        border-radius: 10px;
        border: none;
        background: linear-gradient(135deg, #10b981, #059669);
        color: white;
        font-weight: 600;
        font-size: 0.8125rem;
        cursor: pointer;
        transition: all 0.2s;
        box-shadow: 0 0 20px rgba(16, 185, 129, 0.2);
    }
    .btn-deploy:hover {
        box-shadow: 0 0 30px rgba(16, 185, 129, 0.35);
        transform: translateY(-1px);
    }
    .btn-deploy:disabled {
        opacity: 0.5;
        cursor: not-allowed;
        transform: none;
    }

    /* Stats Bar */
    .stats-bar {
        display: flex;
        align-items: center;
        gap: 1rem;
        padding: 0.75rem 1.25rem;
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
    }
    .stat-pill {
        display: flex;
        align-items: center;
        gap: 0.375rem;
    }
    .pill-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
    }
    .pill-dot.small {
        width: 6px;
        height: 6px;
    }
    .pill-dot.critical {
        background: #ef4444;
    }
    .pill-dot.high {
        background: #f59e0b;
    }
    .pill-dot.medium {
        background: #3b82f6;
    }
    .pill-label {
        font-size: 0.75rem;
        color: #888;
        font-weight: 500;
    }
    .stat-pill.active {
        color: #10b981;
    }
    .stat-pill.active .pill-label {
        color: #10b981;
    }
    .divider {
        width: 1px;
        height: 16px;
        background: #333;
    }

    /* Filters */
    .filters {
        display: flex;
        align-items: center;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .search-box {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 8px;
        padding: 0.5rem 0.75rem;
        color: #555;
        flex: 1;
        min-width: 200px;
    }
    .search-box input {
        flex: 1;
        background: none;
        border: none;
        color: white;
        font-size: 0.8125rem;
        outline: none;
    }
    .search-box input::placeholder {
        color: #444;
    }
    .filter-tabs {
        display: flex;
        gap: 0.25rem;
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 8px;
        padding: 0.25rem;
    }
    .filter-tabs button {
        display: flex;
        align-items: center;
        gap: 0.375rem;
        padding: 0.375rem 0.75rem;
        border-radius: 6px;
        border: none;
        background: transparent;
        color: #666;
        font-size: 0.75rem;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.15s;
    }
    .filter-tabs button:hover {
        color: #aaa;
    }
    .filter-tabs button.active {
        background: #1a1a2e;
        color: white;
    }

    /* Rules List */
    .rules-list {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
    }
    .rule-card {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #0a0a0f;
        border: 1px solid #1a1a2e;
        border-radius: 12px;
        padding: 1rem 1.25rem;
        transition: all 0.2s;
        gap: 1rem;
    }
    .rule-card:hover {
        border-color: #2a2a3e;
    }
    .rule-card.disabled {
        opacity: 0.5;
    }
    .rule-left {
        display: flex;
        gap: 1rem;
        flex: 1;
        min-width: 0;
    }
    .rule-icon {
        width: 36px;
        height: 36px;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #111118;
        flex-shrink: 0;
    }
    .rule-info {
        flex: 1;
        min-width: 0;
    }
    .rule-name-row {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        flex-wrap: wrap;
        margin-bottom: 0.375rem;
    }
    .rule-name {
        font-weight: 700;
        color: white;
        font-size: 0.875rem;
    }
    .owasp-badge {
        font-size: 0.5625rem;
        font-weight: 700;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        background: #3b82f615;
        color: #3b82f6;
        letter-spacing: 0.05em;
    }
    .severity-badge {
        font-size: 0.5625rem;
        font-weight: 700;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .severity-badge.critical {
        background: #ef444415;
        color: #ef4444;
    }
    .severity-badge.high {
        background: #f59e0b15;
        color: #f59e0b;
    }
    .severity-badge.medium {
        background: #3b82f615;
        color: #3b82f6;
    }
    .rule-desc {
        font-size: 0.75rem;
        color: #666;
        margin: 0 0 0.5rem;
        line-height: 1.4;
    }
    .rule-meta {
        display: flex;
        flex-direction: column;
        gap: 0.375rem;
    }
    .pattern-preview {
        font-family: "JetBrains Mono", "Fira Code", monospace;
        font-size: 0.625rem;
        color: #444;
        background: #08080d;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        display: inline-block;
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .rule-tags {
        display: flex;
        gap: 0.25rem;
        flex-wrap: wrap;
    }
    .tag {
        font-size: 0.5625rem;
        padding: 0.0625rem 0.375rem;
        border-radius: 3px;
        background: #ffffff08;
        color: #555;
        font-weight: 500;
    }

    .rule-right {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        flex-shrink: 0;
    }
    .deployed-badge {
        font-size: 0.625rem;
        color: #10b981;
        font-weight: 600;
        letter-spacing: 0.05em;
    }

    /* Toggle */
    .rule-toggle {
        width: 40px;
        height: 22px;
        border-radius: 11px;
        border: none;
        background: #222;
        cursor: pointer;
        position: relative;
        transition: background 0.3s;
        flex-shrink: 0;
    }
    .rule-toggle.on {
        background: linear-gradient(135deg, #10b981, #059669);
    }
    .rule-toggle .toggle-knob {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 18px;
        height: 18px;
        border-radius: 50%;
        background: white;
        transition: transform 0.3s ease;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
    }
    .rule-toggle.on .toggle-knob {
        transform: translateX(18px);
    }

    /* Empty */
    .empty-state {
        text-align: center;
        padding: 4rem 2rem;
        color: #444;
    }
    .empty-state p {
        margin-top: 1rem;
    }

    /* Toast */
    .toast {
        position: fixed;
        bottom: 2rem;
        left: 50%;
        transform: translateX(-50%);
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.75rem 1.25rem;
        border-radius: 999px;
        font-size: 0.8125rem;
        font-weight: 500;
        z-index: 60;
        background: #111;
        border: 1px solid #333;
        color: white;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5);
    }
    .toast.success {
        border-color: #10b98133;
    }
    .toast.error {
        border-color: #ef444433;
    }

    :global(.spin) {
        animation: spin 1s linear infinite;
    }
    @keyframes spin {
        from {
            transform: rotate(0deg);
        }
        to {
            transform: rotate(360deg);
        }
    }

    @media (max-width: 768px) {
        .rule-card {
            flex-direction: column;
            align-items: stretch;
        }
        .rule-right {
            justify-content: flex-end;
        }
        .stats-bar {
            flex-wrap: wrap;
        }
    }

    /* Delete Buttons */
    .btn-delete {
        width: 30px;
        height: 30px;
        border-radius: 6px;
        border: 1px solid #ef444433;
        background: #ef444410;
        color: #ef4444;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
    }
    .btn-delete:hover {
        background: #ef444425;
        border-color: #ef444455;
    }
    .btn-delete-sm {
        width: 24px;
        height: 24px;
        border-radius: 4px;
        border: 1px solid #ef444433;
        background: transparent;
        color: #ef4444;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
        flex-shrink: 0;
    }
    .btn-delete-sm:hover {
        background: #ef444415;
    }

    /* Legacy Section */
    .legacy-section {
        margin-top: 2rem;
        background: #0a0a0f;
        border: 1px solid #ef444422;
        border-radius: 12px;
        overflow: hidden;
    }
    .legacy-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1rem 1.25rem;
        border-bottom: 1px solid #1a1a2e;
    }
    .legacy-header h3 {
        font-size: 0.875rem;
        font-weight: 600;
        color: #ef4444;
        margin: 0;
    }
    .legacy-desc {
        font-size: 0.6875rem;
        color: #555;
        margin: 0.25rem 0 0;
    }
    .btn-cleanup {
        display: flex;
        align-items: center;
        gap: 0.375rem;
        padding: 0.5rem 1rem;
        border-radius: 8px;
        border: 1px solid #ef444433;
        background: #ef444415;
        color: #ef4444;
        font-size: 0.75rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        white-space: nowrap;
    }
    .btn-cleanup:hover {
        background: #ef444425;
        border-color: #ef444455;
    }
    .btn-cleanup:disabled {
        opacity: 0.5;
        cursor: not-allowed;
    }
    .legacy-list {
        padding: 0;
    }
    .legacy-item {
        display: flex;
        align-items: center;
        gap: 0.75rem;
        padding: 0.5rem 1.25rem;
        border-bottom: 1px solid #111118;
    }
    .legacy-item:last-child {
        border-bottom: none;
    }
    .legacy-id {
        font-family: "JetBrains Mono", monospace;
        font-size: 0.6875rem;
        color: #555;
        background: #ffffff08;
        padding: 0.125rem 0.375rem;
        border-radius: 3px;
        flex-shrink: 0;
    }
    .legacy-name {
        flex: 1;
        font-size: 0.75rem;
        color: #666;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .legacy-more {
        padding: 0.75rem 1.25rem;
        text-align: center;
        font-size: 0.6875rem;
        color: #444;
    }
</style>
