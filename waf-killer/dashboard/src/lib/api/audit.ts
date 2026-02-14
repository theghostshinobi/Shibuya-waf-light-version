// dashboard/src/lib/api/audit.ts

import { get } from "$lib/api/client";

export const api = {
    getActivityFeed: () => get('/api/activity'),
    getAuditLogs: () => get('/api/audit'),
    exportAuditLogs: () => get('/api/audit/export'),
};
