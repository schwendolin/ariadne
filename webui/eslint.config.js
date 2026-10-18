// ESLint-Konfiguration der Ariadne-Web-UI.
//
// Die Sicherheitsregeln setzen Architektur 7.7 durch: Zieldaten sind feindlich,
// deshalb wird nie HTML aus Strings erzeugt. Die einzige Ausnahme ist
// src/lib/safe/SafeMarkdown.svelte (markdown-it mit html:false, danach DOMPurify).
// tests/lint-rules.test.ts prüft, dass diese Regeln aktiv bleiben.
import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';
import svelteConfig from './svelte.config.js';

const HTML_SINK = 'Zieldaten sind feindlich: kein HTML aus Strings. Text über {…} bzw. textContent, Markdown nur über SafeMarkdown.svelte.';

const htmlSinks = [
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'createContextualFragment',
  'setHTMLUnsafe',
  'parseHTMLUnsafe',
  'srcdoc',
].map((property) => ({ property, message: HTML_SINK }));

const securityRules = {
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-restricted-properties': [
    'error',
    ...htmlSinks,
    { object: 'document', property: 'write', message: HTML_SINK },
    { object: 'document', property: 'writeln', message: HTML_SINK },
    { object: 'window', property: 'open', message: 'Ziel-URLs werden nie direkt geöffnet (Architektur 7.7).' },
    { object: 'window', property: 'localStorage', message: 'Kein localStorage (E112): Vorlieben auf dem Server, Ansicht in der URL.' },
    { object: 'globalThis', property: 'localStorage', message: 'Kein localStorage (E112): Vorlieben auf dem Server, Ansicht in der URL.' },
    { object: 'window', property: 'sessionStorage', message: 'sessionStorage nur in src/lib/api/auth.ts (Token dieses Tabs).' },
    { object: 'navigator', property: 'clipboard', message: 'Zwischenablage nur über src/lib/util/clipboard.ts (nie Secrets, E111).' },
    { object: 'console', property: 'log', message: 'Kein console.log: nie Token, Code oder Zieldaten in der Konsole.' },
    { object: 'console', property: 'info', message: 'Kein console.info: nie Token, Code oder Zieldaten in der Konsole.' },
    { object: 'console', property: 'debug', message: 'Kein console.debug: nie Token, Code oder Zieldaten in der Konsole.' },
  ],
  'no-restricted-globals': [
    'error',
    { name: 'localStorage', message: 'Kein localStorage (E112): Vorlieben auf dem Server, Ansicht in der URL.' },
    { name: 'sessionStorage', message: 'sessionStorage nur in src/lib/api/auth.ts (Token dieses Tabs).' },
    { name: 'indexedDB', message: 'Kein IndexedDB: nichts im Browser speichern (Briefing 9.12).' },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: 'Property[key.name=/^(allowHTML|allowHtml|unsafeHTML|unsafeHtml|html|dangerouslySetInnerHTML)$/]:not([value.value=false])',
      message: 'Bibliotheksoptionen, die HTML erlauben, sind verboten (Architektur 7.7).',
    },
    {
      selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value=/^(style|srcdoc|href|src|on.*)$/i]",
      message: 'Keine Style-, URL- oder Event-Attribute per setAttribute. Styles nur über Klassen oder CSSOM (styleProps).',
    },
    {
      selector: "CallExpression[callee.object.name='document'][callee.property.name='createElement'][arguments.0.value=/^(script|style|iframe|object|embed)$/i]",
      message: 'Keine dynamischen script-, style- oder iframe-Elemente (CSP).',
    },
  ],
  'no-restricted-imports': [
    'error',
    {
      paths: [
        { name: 'dompurify', message: 'DOMPurify nur in SafeMarkdown.svelte.' },
        { name: 'markdown-it', message: 'markdown-it nur in SafeMarkdown.svelte.' },
      ],
    },
  ],
};

export default defineConfig([
  globalIgnores(['node_modules/', 'dist/', '../src/', '.e2e/', 'test-results/', 'playwright-report/']),
  js.configs.recommended,
  ...ts.configs.recommended,
  ...svelte.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    rules: {
      ...securityRules,
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
    },
  },
  {
    files: ['**/*.svelte', '**/*.svelte.ts'],
    languageOptions: {
      parserOptions: {
        parser: ts.parser,
        extraFileExtensions: ['.svelte'],
        svelteConfig,
      },
    },
    rules: {
      'svelte/no-at-html-tags': 'error',
      'svelte/no-inline-styles': 'error',
      'svelte/no-target-blank': 'error',
      'svelte/require-each-key': 'error',
      'svelte/button-has-type': 'error',
      'svelte/no-useless-mustaches': 'error',
      // Absicht: Listen im Zustand werden nur als Ganzes ersetzt ($state.raw), interne
      // Hilfsmengen (Ladezustand, platzierte Knoten) sind bewusst nicht reaktiv.
      'svelte/prefer-svelte-reactivity': 'off',
    },
  },
  {
    // Einzige Ausnahme: Markdown für Notizen (markdown-it html:false, dann DOMPurify).
    files: ['src/lib/safe/SafeMarkdown.svelte'],
    rules: {
      'no-restricted-imports': 'off',
    },
  },
  {
    // Einziger Zugang zu sessionStorage (Token dieses Tabs). localStorage bleibt auch hier verboten.
    files: ['src/lib/api/auth.ts'],
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'localStorage', message: 'Kein localStorage (E112).' },
        { name: 'indexedDB', message: 'Kein IndexedDB.' },
      ],
      'no-restricted-properties': ['error', ...htmlSinks],
    },
  },
  {
    // Einzige Stelle mit navigator.clipboard (nur Befehle, Werte, Belege; nie Secrets).
    files: ['src/lib/util/clipboard.ts'],
    rules: {
      'no-restricted-properties': ['error', ...htmlSinks],
    },
  },
  {
    files: ['*.config.js', '*.config.ts', 'tests/**/*.ts', 'src/**/*.test.ts'],
    languageOptions: {
      globals: { ...globals.node, ...globals.browser },
    },
  },
  {
    // Tests dürfen Storages direkt prüfen (z. B. dass kein Token in localStorage liegt).
    files: ['tests/**/*.ts', 'src/**/*.test.ts'],
    rules: {
      'no-restricted-globals': 'off',
      'no-restricted-properties': ['error', ...htmlSinks],
    },
  },
]);
