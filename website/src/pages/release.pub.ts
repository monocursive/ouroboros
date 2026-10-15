import type { APIRoute } from 'astro';
// The maintainer release key, served from the copy the release tooling pins.
import key from '../../../crates/ukai-jail/dist/release.pub?raw';

export const GET: APIRoute = () => new Response(key, {
  headers: { 'Content-Type': 'text/plain; charset=utf-8' },
});
