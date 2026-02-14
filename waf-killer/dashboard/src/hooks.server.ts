import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';

export const handle: Handle = async ({ event, resolve }) => {
    const { pathname } = event.url;


    // Server-side auth check removed to support client-side token auth
    // The client will handle redirection if the token is missing or invalid.

    return resolve(event);
};
