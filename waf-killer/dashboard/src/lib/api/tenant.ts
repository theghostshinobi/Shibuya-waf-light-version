// dashboard/src/lib/api/tenant.ts

import { get, post, del } from "$lib/api/client";

export const api = {
    getTeamMembers: () => get('/api/team'),
    inviteMember: (email: string, role: string) => post('/api/team/invite', { email, role }),
    removeMember: (id: string) => del(`/api/team/${id}`),
    getTenant: () => get('/api/tenant'),
    updateSettings: (settings: any) => post('/api/tenant/settings', settings),
};
