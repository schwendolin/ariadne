/**
 * Einstieg der SPA. Keine Inline-Skripte: index.html lädt nur dieses Modul. Besitzer: ui-fundament.
 *
 * Reihenfolge: Einmalcode aus dem Fragment nehmen (und das Fragment sofort entfernen), Backend
 * wählen (Daemon oder Mock), Tastatur installieren, App starten. Theme: bis die Vorlieben vom
 * Server da sind, folgt die Oberfläche dem System (kein Browser-Speicher, E112).
 */
import './app.css';
import { mount } from 'svelte';
import App from './App.svelte';
import { takeCodeFromLocation } from './lib/api/auth';
import { selectBackend } from './lib/api/select';
import { installKeymap } from './lib/keys/keymap';
import { AppState } from './lib/stores/app.svelte';

const code = takeCodeFromLocation();
const backend = await selectBackend();
const app = new AppState(backend);
installKeymap(window);
const target = document.getElementById('app');
if (target) {
  mount(App, { target, props: { app } });
  void app.start(code);
}
