<script lang="ts">
    import { onMount } from "svelte";
    import api from "$lib/api/client";
    import {
        Users,
        Plus,
        Pencil,
        Trash2,
        Globe,
        Calendar,
        CreditCard,
        Lock,
        Search,
        ListFilter,
        EllipsisVertical,
        CircleCheck,
        CircleX,
        CircleAlert,
        ExternalLink,
        Shield,
    } from "lucide-svelte";
    import { fade, fly, slide } from "svelte/transition";

    interface Tenant {
        id: string;
        slug: string;
        name: string;
        plan: string;
        status: string;
        created_at: string;
    }

    let tenants: Tenant[] = [];
    let loading = true;
    let showModal = false;
    let editingTenant: Tenant | null = null;
    let searchTerm = "";

    // Form state
    let formData = {
        name: "",
        slug: "",
        plan: "free",
        status: "active",
    };

    onMount(async () => {
        await loadTenants();
    });

    async function loadTenants() {
        loading = true;
        try {
            const response = await api.getTenants();
            tenants = response.tenants || [];
        } catch (err) {
            console.error("Failed to load tenants:", err);
        } finally {
            loading = false;
        }
    }

    function openCreateModal() {
        editingTenant = null;
        formData = { name: "", slug: "", plan: "free", status: "active" };
        showModal = true;
    }

    function openEditModal(tenant: Tenant) {
        editingTenant = tenant;
        formData = {
            name: tenant.name,
            slug: tenant.slug,
            plan: tenant.plan.toLowerCase(),
            status: tenant.status.toLowerCase(),
        };
        showModal = true;
    }

    async function handleSubmit() {
        try {
            if (editingTenant) {
                await api.updateTenant(editingTenant.id, formData);
            } else {
                // For creation, we might need more fields if the backend requires them,
                // but TenantStore.create defaults them.
                await api.createTenant({
                    ...formData,
                    settings: {
                        primary_color: "#4F46E5",
                        timezone: "UTC",
                        retention_days: 7,
                    },
                });
            }
            showModal = false;
            await loadTenants();
        } catch (err) {
            alert("Failed to save tenant: " + err);
        }
    }

    async function handleDelete(tenant: Tenant) {
        if (tenant.slug === "default") {
            alert("Cannot delete default tenant");
            return;
        }

        if (
            !confirm(
                `Are you sure you want to disable tenant "${tenant.name}"?`,
            )
        ) {
            return;
        }

        try {
            await api.deleteTenant(tenant.id);
            await loadTenants();
        } catch (err) {
            alert("Failed to delete tenant: " + err);
        }
    }

    function getStatusIcon(status: string) {
        switch (status.toLowerCase()) {
            case "active":
                return {
                    icon: CircleCheck,
                    color: "text-emerald-500",
                    bg: "bg-emerald-500/10",
                };
            case "suspended":
                return {
                    icon: CircleAlert,
                    color: "text-amber-500",
                    bg: "bg-amber-500/10",
                };
            case "disabled":
                return {
                    icon: CircleX,
                    color: "text-rose-500",
                    bg: "bg-rose-500/10",
                };
            default:
                return {
                    icon: Lock,
                    color: "text-gray-500",
                    bg: "bg-gray-500/10",
                };
        }
    }

    function getPlanColor(plan: string) {
        switch (plan.toLowerCase()) {
            case "enterprise":
                return "text-purple-400 bg-purple-400/10 border-purple-400/20";
            case "business":
                return "text-blue-400 bg-blue-400/10 border-blue-400/20";
            case "startup":
                return "text-cyan-400 bg-cyan-400/10 border-cyan-400/20";
            default:
                return "text-gray-400 bg-gray-400/10 border-gray-400/20";
        }
    }

    $: filteredTenants = tenants.filter(
        (t) =>
            t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            t.slug.toLowerCase().includes(searchTerm.toLowerCase()),
    );
</script>

<div
    class="p-8 max-w-7xl mx-auto space-y-8 min-h-screen bg-black text-white selection:bg-white/20"
>
    <!-- Header Section -->
    <div
        class="flex flex-col md:flex-row md:items-center justify-between gap-4"
    >
        <div>
            <h1
                class="text-3xl font-bold tracking-tight bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent"
            >
                Tenants Management
            </h1>
            <p class="text-gray-500 text-sm mt-1">
                Manage multi-tenant isolation, billing plans, and organizational
                access.
            </p>
        </div>
        <button
            on:click={openCreateModal}
            class="flex items-center gap-2 bg-white text-black px-4 py-2 rounded-lg font-medium hover:bg-gray-200 transition-all active:scale-95"
        >
            <Plus size={18} />
            Create Tenant
        </button>
    </div>

    <!-- Stats Grid (Visual Appeal) -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-[#111] border border-[#222] p-6 rounded-2xl space-y-2">
            <div
                class="text-gray-500 text-xs font-mono uppercase tracking-widest"
            >
                Total Organizations
            </div>
            <div class="text-4xl font-bold">{tenants.length}</div>
            <div class="text-emerald-500 text-xs flex items-center gap-1">
                <CircleCheck size={12} /> Live Infrastructure
            </div>
        </div>
        <div class="bg-[#111] border border-[#222] p-6 rounded-2xl space-y-2">
            <div
                class="text-gray-500 text-xs font-mono uppercase tracking-widest"
            >
                Active Isolation
            </div>
            <div class="text-4xl font-bold">
                {tenants.filter((t) => t.status.toLowerCase() === "active")
                    .length}
            </div>
            <div class="text-blue-500 text-xs flex items-center gap-1">
                <Shield size={12} /> Namespace Secured
            </div>
        </div>
        <div class="bg-[#111] border border-[#222] p-6 rounded-2xl space-y-2">
            <div
                class="text-gray-500 text-xs font-mono uppercase tracking-widest"
            >
                Enterprise Tier
            </div>
            <div class="text-4xl font-bold">
                {tenants.filter((t) => t.plan.toLowerCase() === "enterprise")
                    .length}
            </div>
            <div class="text-purple-500 text-xs flex items-center gap-1">
                <CreditCard size={12} /> High-Scale Logic
            </div>
        </div>
    </div>

    <!-- Controls & Table -->
    <div
        class="bg-[#0a0a0a] border border-[#1a1a1a] rounded-2xl overflow-hidden shadow-2xl"
    >
        <!-- Table Toolbar -->
        <div
            class="p-4 border-b border-[#1a1a1a] flex flex-col sm:flex-row gap-4 justify-between bg-[#0a0a0a]"
        >
            <div class="relative flex-1 max-w-md">
                <Search
                    class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                    size={18}
                />
                <input
                    type="text"
                    bind:value={searchTerm}
                    placeholder="Search by name or slug..."
                    class="w-full bg-black border border-[#222] rounded-xl pl-10 pr-4 py-2 text-sm focus:border-white/40 focus:outline-none transition-colors"
                />
            </div>
            <div class="flex items-center gap-2">
                <button
                    class="p-2 border border-[#222] rounded-xl text-gray-400 hover:text-white transition-colors"
                >
                    <ListFilter size={18} />
                </button>
                <button
                    on:click={loadTenants}
                    class="px-4 py-2 border border-[#222] rounded-xl text-sm text-gray-400 hover:text-white transition-colors"
                >
                    Refresh
                </button>
            </div>
        </div>

        <!-- The actual table -->
        <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse">
                <thead
                    class="bg-[#0f0f0f] text-[11px] font-mono text-gray-500 uppercase tracking-wider"
                >
                    <tr>
                        <th class="px-6 py-4 font-medium"
                            >Organization / Slug</th
                        >
                        <th class="px-6 py-4 font-medium text-center">Plan</th>
                        <th class="px-6 py-4 font-medium text-center">Status</th
                        >
                        <th class="px-6 py-4 font-medium">Created</th>
                        <th class="px-6 py-4 font-medium text-right">Actions</th
                        >
                    </tr>
                </thead>
                <tbody class="divide-y divide-[#1a1a1a]">
                    {#if loading}
                        {#each Array(5) as _}
                            <tr class="animate-pulse">
                                <td class="px-6 py-6"
                                    ><div
                                        class="h-4 w-32 bg-[#1a1a1a] rounded"
                                    ></div></td
                                >
                                <td class="px-6 py-6"
                                    ><div
                                        class="h-4 w-16 bg-[#1a1a1a] rounded mx-auto"
                                    ></div></td
                                >
                                <td class="px-6 py-6"
                                    ><div
                                        class="h-4 w-20 bg-[#1a1a1a] rounded mx-auto"
                                    ></div></td
                                >
                                <td class="px-6 py-6"
                                    ><div
                                        class="h-4 w-24 bg-[#1a1a1a] rounded"
                                    ></div></td
                                >
                                <td class="px-6 py-6"
                                    ><div
                                        class="h-4 w-12 bg-[#1a1a1a] rounded ml-auto"
                                    ></div></td
                                >
                            </tr>
                        {/each}
                    {:else}
                        {#each filteredTenants as tenant (tenant.id)}
                            {@const status = getStatusIcon(tenant.status)}
                            <tr
                                class="group hover:bg-white/[0.02] transition-colors"
                                in:fade
                            >
                                <td class="px-6 py-4">
                                    <div class="flex items-center gap-3">
                                        <div
                                            class="w-10 h-10 rounded-xl bg-gradient-to-br from-gray-700 to-gray-900 flex items-center justify-center text-lg font-bold border border-[#222]"
                                        >
                                            {tenant.name.charAt(0)}
                                        </div>
                                        <div>
                                            <div
                                                class="font-medium text-sm text-white"
                                            >
                                                {tenant.name}
                                            </div>
                                            <div
                                                class="text-[10px] font-mono text-gray-500"
                                            >
                                                {tenant.slug}
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4 text-center">
                                    <span
                                        class="inline-block px-2 py-0.5 text-[10px] font-bold rounded border uppercase {getPlanColor(
                                            tenant.plan,
                                        )}"
                                    >
                                        {tenant.plan}
                                    </span>
                                </td>
                                <td class="px-6 py-4">
                                    <div
                                        class="flex items-center justify-center"
                                    >
                                        <div
                                            class="flex items-center gap-1.5 px-2.5 py-1 rounded-full {status.bg} border border-current opacity-70"
                                        >
                                            <svelte:component
                                                this={status.icon}
                                                size={12}
                                                class={status.color}
                                            />
                                            <span
                                                class="text-[10px] font-semibold uppercase {status.color} tracking-tighter"
                                                >{tenant.status}</span
                                            >
                                        </div>
                                    </div>
                                </td>
                                <td
                                    class="px-6 py-4 text-sm text-gray-400 font-mono"
                                >
                                    {new Date(
                                        tenant.created_at,
                                    ).toLocaleDateString()}
                                </td>
                                <td class="px-6 py-4 text-right">
                                    <div
                                        class="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                                    >
                                        <button
                                            on:click={() =>
                                                openEditModal(tenant)}
                                            class="p-2 text-gray-500 hover:text-white hover:bg-white/10 rounded-lg transition-all"
                                        >
                                            <Pencil size={16} />
                                        </button>
                                        <button
                                            on:click={() =>
                                                handleDelete(tenant)}
                                            disabled={tenant.slug === "default"}
                                            class="p-2 text-gray-500 hover:text-rose-500 hover:bg-rose-500/10 rounded-lg transition-all disabled:opacity-30"
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        {/each}
                    {/if}
                </tbody>
            </table>
            {#if !loading && filteredTenants.length === 0}
                <div class="p-12 text-center text-gray-500">
                    <Globe size={48} class="mx-auto mb-4 opacity-10" />
                    <p>No organizations found matching your search.</p>
                </div>
            {/if}
        </div>
    </div>
</div>

<!-- Modal Component -->
{#if showModal}
    <div
        class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md"
        in:fade
    >
        <div
            class="bg-[#0a0a0a] border border-[#1a1a1a] rounded-3xl w-full max-w-md shadow-2xl p-8 space-y-6"
            in:fly={{ y: 20 }}
        >
            <div class="flex items-center justify-between">
                <h2 class="text-xl font-bold">
                    {editingTenant ? "Configure Tenant" : "New Organization"}
                </h2>
                <button
                    on:click={() => (showModal = false)}
                    class="text-gray-500 hover:text-white"
                >
                    <CircleX size={24} />
                </button>
            </div>

            <form on:submit|preventDefault={handleSubmit} class="space-y-4">
                <div class="space-y-1.5">
                    <label
                        class="text-[11px] font-mono text-gray-500 uppercase tracking-widest pl-1"
                        >Display Name</label
                    >
                    <input
                        bind:value={formData.name}
                        required
                        placeholder="Acme Corp"
                        class="w-full bg-black border border-[#222] rounded-xl px-4 py-2.5 text-sm focus:border-white/40 focus:outline-none"
                    />
                </div>

                <div class="space-y-1.5">
                    <label
                        class="text-[11px] font-mono text-gray-500 uppercase tracking-widest pl-1"
                        >Identifier Slug</label
                    >
                    <input
                        bind:value={formData.slug}
                        required
                        disabled={!!editingTenant}
                        placeholder="acme-corp"
                        class="w-full bg-black border border-[#222] rounded-xl px-4 py-2.5 text-sm focus:border-white/40 focus:outline-none disabled:opacity-50 font-mono"
                    />
                    {#if !editingTenant}
                        <p class="text-[10px] text-gray-600 pl-1 italic">
                            Used for isolation headers & API paths.
                        </p>
                    {/if}
                </div>

                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-1.5">
                        <label
                            class="text-[11px] font-mono text-gray-500 uppercase tracking-widest pl-1"
                            >Pricing Plan</label
                        >
                        <select
                            bind:value={formData.plan}
                            class="w-full bg-black border border-[#222] rounded-xl px-3 py-2.5 text-sm focus:border-white/40 focus:outline-none appearance-none"
                        >
                            <option value="free">Free Tier</option>
                            <option value="startup">Startup</option>
                            <option value="business">Business</option>
                            <option value="enterprise">Enterprise</option>
                        </select>
                    </div>
                    <div class="space-y-1.5">
                        <label
                            class="text-[11px] font-mono text-gray-500 uppercase tracking-widest pl-1"
                            >Status</label
                        >
                        <select
                            bind:value={formData.status}
                            class="w-full bg-black border border-[#222] rounded-xl px-3 py-2.5 text-sm focus:border-white/40 focus:outline-none appearance-none"
                        >
                            <option value="active">Active</option>
                            <option value="suspended">Suspended</option>
                            <option value="disabled">Disabled</option>
                        </select>
                    </div>
                </div>

                <div class="pt-4 flex gap-3">
                    <button
                        type="button"
                        on:click={() => (showModal = false)}
                        class="flex-1 py-3 border border-[#222] rounded-xl font-medium hover:bg-white/5 transition-all outline-none"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        class="flex-1 py-3 bg-white text-black rounded-xl font-bold hover:bg-gray-200 transition-all active:scale-95 outline-none"
                    >
                        {editingTenant ? "Apply Changes" : "Initialize Tenant"}
                    </button>
                </div>
            </form>
        </div>
    </div>
{/if}

<style>
    /* Custom scrollbar for table */
    .overflow-x-auto::-webkit-scrollbar {
        height: 4px;
    }
    .overflow-x-auto::-webkit-scrollbar-track {
        background: transparent;
    }
    .overflow-x-auto::-webkit-scrollbar-thumb {
        background: #222;
        border-radius: 10px;
    }
</style>
