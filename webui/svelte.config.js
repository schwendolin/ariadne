// Svelte-Konfiguration. Kein SvelteKit: die UI ist eine SPA mit eigenem Router.
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/vite-plugin-svelte').SvelteConfig} */
export default {
  preprocess: vitePreprocess(),
  compilerOptions: {
    // Runes überall, keine Legacy-Syntax.
    runes: true,
  },
};
