/// <reference types="vitest/config" />
// Vite-Konfiguration der Ariadne-Web-UI.
//
// Sicherheitsrelevante Punkte (Architektur 7.2, 7.7):
// * Der Build schreibt nach ../src/ariadne/web/static (gitignored, landet im Wheel).
// * Keine Inline-Skripte: Vite bindet nur externe Module ein, das Modulepreload-Polyfill
//   ist aus, und es gibt keine data:-URIs (assetsInlineLimit 0), weil die CSP
//   img-src nur 'self' und blob: erlaubt.
// * `vite preview` setzt dieselbe CSP wie der Daemon. So fällt jede Verletzung
//   (Inline-Style, Inline-Skript) schon lokal auf.
// * Der Mock-Modus wird nur gebaut, wenn er ausdrücklich verlangt ist
//   (--mode mock oder VITE_ARIADNE_MOCK=1). Im normalen Build ist er per
//   Konstante abgeschaltet und wird vom Bundler entfernt.
import { defineConfig, loadEnv } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// Genau die CSP aus Architektur 7.2.4. Kein font-src: die UI nutzt nur Systemschriften,
// default-src 'none' sperrt damit jede Schriftdatei (fällt im Preview-Lauf sofort auf).
export const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' blob:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const SECURITY_HEADERS = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store',
};

// Der Daemon prüft Host und Origin exakt (Architektur 7.2). Der Dev-Proxy
// gibt sich deshalb als die UI des Daemons aus.
const DAEMON = process.env.ARIADNE_DAEMON_URL ?? 'http://127.0.0.1:7330';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const mock = mode === 'mock' || env.VITE_ARIADNE_MOCK === '1' || process.env.VITE_ARIADNE_MOCK === '1';
  const isTest = Boolean(process.env.VITEST);

  return {
    plugins: [svelte(), ...(isTest ? [svelteTesting()] : [])],
    define: {
      __ARIADNE_MOCK__: JSON.stringify(mock),
      __ARIADNE_VERSION__: JSON.stringify(process.env.npm_package_version ?? '0.0.0'),
    },
    build: {
      outDir: '../src/ariadne/web/static',
      emptyOutDir: true,
      target: 'es2022',
      assetsInlineLimit: 0,
      modulePreload: { polyfill: false },
      sourcemap: false,
      cssCodeSplit: true,
      reportCompressedSize: false,
      // Die UI kommt lokal vom Daemon (kein Netz dazwischen); Cytoscape liegt ohnehin in einem
      // eigenen Chunk. Der Rest (Svelte, markdown-it, DOMPurify) bleibt bewusst ein Bündel.
      chunkSizeWarningLimit: 800,
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': {
          target: DAEMON,
          changeOrigin: true,
          configure(proxy) {
            proxy.on('proxyReq', (req) => {
              req.setHeader('origin', DAEMON);
            });
          },
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      strictPort: true,
      headers: SECURITY_HEADERS,
    },
    test: {
      environment: 'jsdom',
      include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
      setupFiles: ['./tests/setup.ts'],
      restoreMocks: true,
      testTimeout: 20000,
    },
  };
});
