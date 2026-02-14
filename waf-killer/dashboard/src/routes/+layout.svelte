<script lang="ts">
  import "../app.css";
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
  import { browser } from "$app/environment";
  import {
    LayoutDashboard,
    List,
    Activity,
    Shield,
    Brain,
    Bot,
    Settings,
    LogOut,
    TriangleAlert,
    Menu,
    X,
    Ghost,
    Bug,
    Bandage,
    FileText,
    ShieldCheck,
    Users,
    Plus,
    Pencil,
    Trash2,
    Globe,
    Calendar,
    CreditCard,
    Lock,
    Search,
    Sliders,
    EllipsisVertical,
    CircleCheck,
    CircleX,
    CircleAlert,
    ExternalLink,
    BarChart3,
    Zap,
  } from "lucide-svelte";
  import { authStore } from "$lib/stores/auth";
  import { uiModeStore } from "$lib/stores/uiMode";
  import ModeToggle from "$lib/components/ModeToggle.svelte";

  // Full feature list
  const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/requests", label: "Requests", icon: List },
    { href: "/analytics", label: "Analytics", icon: Activity },
    { href: "/rules", label: "Rules", icon: Shield },
    { href: "/ml", label: "ML Engine", icon: Brain },
    { href: "/bot-detection", label: "Bot Detection", icon: Bot },
  ];

  const advancedNavItems = [
    { href: "/tenants", label: "Tenants", icon: Users },
    { href: "/patches", label: "Virtual Patches", icon: Bandage },
    { href: "/shadow", label: "Shadow API", icon: Ghost },
    { href: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
    { href: "/threats", label: "Threat Intel", icon: TriangleAlert },
    { href: "/api-protection", label: "API Protection", icon: ShieldCheck },
    { href: "/audit", label: "Audit Logs", icon: FileText },
    { href: "/metrics", label: "Metrics", icon: BarChart3 },
    { href: "/ebpf", label: "eBPF Kernel", icon: Zap },
    { href: "/settings", label: "Config/Settings", icon: Settings },
  ];

  let mode: "simple" | "advanced";
  uiModeStore.subscribe((v) => (mode = v));

  let isMobileMenuOpen = false;

  // Check if current route is login
  $: isLoginPage = $page.url.pathname === "/login";

  function handleLogout() {
    authStore.logout();
    goto("/login");
  }
</script>

{#if isLoginPage}
  <!-- Full page layout for login -->
  <div class="min-h-screen bg-black text-white">
    <slot />
  </div>
{:else}
  <!-- Dashboard layout with sidebar -->
  <div
    class="flex h-screen w-full overflow-hidden bg-black text-white font-sans antialiased selection:bg-white/20"
  >
    <!-- Sidebar -->
    <aside class="w-64 border-r border-[#333] bg-black hidden md:flex flex-col">
      <!-- Logo -->
      <div class="flex h-16 items-center border-b border-[#333] px-6">
        <div class="flex items-center gap-3">
          <div
            class="w-8 h-8 rounded-full bg-white text-black flex items-center justify-center"
          >
            <Shield size={16} fill="currentColor" />
          </div>
          <div>
            <h1 class="text-sm font-bold text-white tracking-wide">SHIBUYA</h1>
            <p
              class="text-[10px] text-gray-500 uppercase tracking-widest font-mono"
            >
              WAF
            </p>
          </div>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="flex-1 overflow-y-auto py-6 px-4">
        <div class="space-y-0.5">
          <p
            class="px-2 mb-2 text-[11px] font-medium text-gray-500 uppercase tracking-wider"
          >
            Platform
          </p>
          {#each navItems as item}
            <a
              href={item.href}
              class="nav-link group"
              class:active={$page.url.pathname === item.href ||
                (item.href !== "/" && $page.url.pathname.startsWith(item.href))}
            >
              <svelte:component this={item.icon} size={16} class="nav-icon" />
              <span>{item.label}</span>
            </a>
          {/each}
        </div>

        <!-- Always show Advanced items if mode is advanced, or perhaps we simplify and show mostly everything? 
             User asked for "use all features possible... simple and god mode". 
             Let's keep the toggle but make the list comprehensive in Advanced. -->
        {#if mode === "advanced"}
          <div class="mt-8 pt-4 border-t border-[#333]">
            <p
              class="px-2 mb-2 text-[11px] font-medium text-gray-500 uppercase tracking-wider"
            >
              Intelligence & Ops
            </p>
            <div class="space-y-0.5">
              {#each advancedNavItems as item}
                <a
                  href={item.href}
                  class="nav-link group"
                  class:active={$page.url.pathname.startsWith(item.href)}
                >
                  <svelte:component
                    this={item.icon}
                    size={16}
                    class="nav-icon"
                  />
                  <span>{item.label}</span>
                </a>
              {/each}
            </div>
          </div>
        {/if}
      </nav>

      <!-- Sidebar footer -->
      <div class="p-4 border-t border-[#333]">
        <button
          on:click={handleLogout}
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-400
                           hover:text-white hover:bg-[#111] rounded-md transition-colors"
        >
          <LogOut size={16} />
          <span>Logout</span>
        </button>
      </div>
    </aside>

    <!-- Main content area -->
    <div class="flex flex-col flex-1 overflow-hidden bg-black">
      <!-- Mobile Menu Overlay -->
      {#if isMobileMenuOpen}
        <div
          class="fixed inset-0 bg-black/80 z-40 md:hidden backdrop-blur-sm"
          on:click={() => (isMobileMenuOpen = false)}
        ></div>

        <div
          class="fixed inset-y-0 left-0 w-64 bg-black border-r border-[#333] z-50 transform transition-transform duration-300 md:hidden"
          class:translate-x-0={isMobileMenuOpen}
          class:-translate-x-full={!isMobileMenuOpen}
        >
          <div
            class="flex h-16 items-center border-b border-[#333] px-6 justify-between"
          >
            <div class="flex items-center gap-3">
              <div
                class="w-8 h-8 rounded-full bg-white text-black flex items-center justify-center"
              >
                <Shield size={16} fill="currentColor" />
              </div>
              <span class="font-bold text-white text-sm">SHIBUYA</span>
            </div>
            <button
              on:click={() => (isMobileMenuOpen = false)}
              class="text-gray-400"
            >
              <X size={20} />
            </button>
          </div>

          <nav class="flex-1 overflow-y-auto py-6 px-4">
            <div class="space-y-0.5">
              <p
                class="px-2 mb-2 text-[11px] font-medium text-gray-500 uppercase tracking-wider"
              >
                Platform
              </p>
              {#each navItems as item}
                <a
                  href={item.href}
                  class="nav-link group"
                  class:active={$page.url.pathname === item.href ||
                    (item.href !== "/" &&
                      $page.url.pathname.startsWith(item.href))}
                  on:click={() => (isMobileMenuOpen = false)}
                >
                  <svelte:component
                    this={item.icon}
                    size={16}
                    class="nav-icon"
                  />
                  <span>{item.label}</span>
                </a>
              {/each}

              {#if mode === "advanced"}
                <div class="mt-6 pt-4 border-t border-[#333]">
                  <p
                    class="px-2 mb-2 text-[11px] font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Advanced
                  </p>
                  {#each advancedNavItems as item}
                    <a
                      href={item.href}
                      class="nav-link group"
                      class:active={$page.url.pathname.startsWith(item.href)}
                      on:click={() => (isMobileMenuOpen = false)}
                    >
                      <svelte:component
                        this={item.icon}
                        size={16}
                        class="nav-icon"
                      />
                      <span>{item.label}</span>
                    </a>
                  {/each}
                </div>
              {/if}
            </div>
          </nav>
        </div>
      {/if}

      <!-- Top header -->
      <header
        class="h-16 border-b border-[#333] bg-black/50 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-30"
      >
        <div class="flex items-center gap-4">
          <!-- Mobile menu button -->
          <button
            on:click={() => (isMobileMenuOpen = !isMobileMenuOpen)}
            class="md:hidden p-2 text-gray-400 hover:text-white"
          >
            <Menu size={20} />
          </button>

          <!-- Breadcrumb placeholder or simple path display -->
          <div class="text-sm text-gray-400 font-mono hidden sm:block">
            guest@shibuya:~$ <span class="text-white">{$page.url.pathname}</span
            >
          </div>
        </div>

        <div class="flex items-center gap-4">
          <ModeToggle />

          <!-- Status indicator -->
          <div
            class="flex items-center gap-2 px-2.5 py-1 bg-[#111] border border-[#333] rounded-full"
          >
            <span class="relative flex h-1.5 w-1.5">
              <span
                class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-75"
              ></span>
              <span
                class="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"
              ></span>
            </span>
            <span
              class="text-[10px] font-medium text-emerald-500 uppercase tracking-wider"
              >Online</span
            >
          </div>
        </div>
      </header>

      <!-- Page content -->
      <main class="flex-1 overflow-y-auto bg-black p-0">
        <slot />
      </main>
    </div>
  </div>
{/if}

<style>
  .nav-link {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0.75rem;
    font-size: 0.875rem;
    color: #888;
    border-radius: 0.375rem;
    transition: all 0.15s ease;
  }

  .nav-link:hover {
    color: #fff;
    background: #111;
  }

  .nav-link.active {
    color: #fff;
    background: #111;
  }

  .nav-link.active .nav-icon {
    color: #fff;
  }

  :global(.nav-icon) {
    color: #666;
    transition: color 0.15s ease;
  }

  .nav-link:hover :global(.nav-icon) {
    color: #fff;
  }
</style>
