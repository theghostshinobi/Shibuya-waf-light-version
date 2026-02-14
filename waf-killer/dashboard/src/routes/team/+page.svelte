<script lang="ts">
    import { onMount } from "svelte";
    import { api } from "$lib/api/client";
    // Mocking api calls for this snippet since we don't have the full client code context

    let members: any[] = [];
    let showInviteModal = false;
    let inviteEmail = "";
    let inviteRole = "Viewer";

    onMount(async () => {
        await fetchMembers();
    });

    async function fetchMembers() {
        // members = await api.getTeamMembers();
        // Placeholder fetch
        try {
            members = await api.getTeamMembers();
        } catch (e) {
            console.error(e);
        }
    }

    async function inviteMember() {
        // await api.inviteTeamMember(email, role);
        try {
            await api.inviteTeamMember(inviteEmail, inviteRole);
            await fetchMembers();
            showInviteModal = false;
            inviteEmail = "";
        } catch (e) {
            console.error("Failed to invite member", e);
        }
    }

    async function removeMember(userId: string) {
        if (confirm("Remove this team member?")) {
            try {
                await api.removeTeamMember(userId);
                members = members.filter((m) => m.user_id !== userId);
            } catch (e) {
                console.error("Failed to remove member", e);
            }
        }
    }

    function formatDate(d) {
        return new Date(d).toLocaleDateString();
    }
</script>

<div class="space-y-6 p-6">
    <div class="flex justify-between items-center">
        <h1 class="text-2xl font-bold">Team Members</h1>
        <button
            class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            on:click={() => (showInviteModal = true)}
        >
            Invite Member
        </button>
    </div>

    <!-- Team table -->
    <div class="bg-white shadow rounded-lg overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th
                        class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >Name</th
                    >
                    <th
                        class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >Email</th
                    >
                    <th
                        class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >Role</th
                    >
                    <th
                        class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >Joined</th
                    >
                    <th
                        class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider"
                        >Actions</th
                    >
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                {#each members as member}
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap">
                            <div class="flex items-center">
                                <div
                                    class="h-8 w-8 rounded-full bg-gray-200 flex items-center justify-center text-sm font-bold text-gray-600"
                                >
                                    {member.name ? member.name.charAt(0) : "?"}
                                </div>
                                <div class="ml-4">
                                    <div
                                        class="text-sm font-medium text-gray-900"
                                    >
                                        {member.name || "Pending"}
                                    </div>
                                </div>
                            </div>
                        </td>
                        <td
                            class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"
                            >{member.email}</td
                        >
                        <td class="px-6 py-4 whitespace-nowrap">
                            <span
                                class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800"
                            >
                                {member.role}
                            </span>
                        </td>
                        <td
                            class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"
                            >{formatDate(member.invited_at)}</td
                        >
                        <td
                            class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium"
                        >
                            {#if member.role !== "Owner"}
                                <button
                                    class="text-red-600 hover:text-red-900"
                                    on:click={() =>
                                        removeMember(member.user_id)}
                                >
                                    Remove
                                </button>
                            {/if}
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
</div>

{#if showInviteModal}
    <div
        class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex items-center justify-center"
    >
        <div class="relative bg-white rounded-lg shadow-xl p-8 max-w-md w-full">
            <h3 class="text-lg font-medium leading-6 text-gray-900 mb-4">
                Invite Team Member
            </h3>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700"
                        >Email</label
                    >
                    <input
                        type="email"
                        bind:value={inviteEmail}
                        class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                    />
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700"
                        >Role</label
                    >
                    <select
                        bind:value={inviteRole}
                        class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm p-2"
                    >
                        <option value="Viewer">Viewer</option>
                        <option value="Analyst">Analyst</option>
                        <option value="SecurityEngineer"
                            >Security Engineer</option
                        >
                        <option value="Admin">Admin</option>
                    </select>
                </div>
            </div>
            <div class="mt-6 flex justify-end gap-2">
                <button
                    class="px-4 py-2 bg-gray-200 rounded hover:bg-gray-300"
                    on:click={() => (showInviteModal = false)}>Cancel</button
                >
                <button
                    class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                    on:click={inviteMember}>Send Invite</button
                >
            </div>
        </div>
    </div>
{/if}
