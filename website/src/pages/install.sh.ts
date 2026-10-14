import type { APIRoute } from 'astro';
// The served installer is the repository's root install.sh, byte for byte.
import script from '../../../install.sh?raw';

export const GET: APIRoute = () => new Response(script, {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
});
