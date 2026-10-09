/**
 * Einstieg der SPA. Keine Inline-Skripte: index.html lädt nur dieses Modul.
 *
 * Reihenfolge: Theme setzen, Einmalcode aus dem Fragment nehmen (und das Fragment
 * sofort entfernen), Backend wählen (Daemon oder Mock), App starten.
 */
import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { takeCodeFromLocation } from './lib/api/auth';
import { selectBackend } from './lib/api/select';
import { AppState } from './lib/stores/app.svelte';
import { initTheme } from './lib/util/theme';

initTheme();
const code = takeCodeFromLocation();
const backend = await selectBackend();
const app = new AppState(backend);
const target = document.getElementById('app');
if (target) {
  mount(App, { target, props: { app } });
  void app.start(code);
}
