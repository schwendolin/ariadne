/**
 * Einmalcode aus der Startdatei (`#c=<code>`), gelesen bevor irgendein anderes Modul läuft.
 *
 * `main.ts` importiert dieses Modul als erstes. ES-Module werden in Importreihenfolge ausgewertet;
 * andere Module (etwa der URL-Zustand, der `/` auf `/karte` umleitet) dürfen das Fragment nicht
 * vorher verlieren oder sehen. Das Fragment ist danach sofort aus der Adresse entfernt
 * (Architektur 7.2, web-api.md 3). Besitzer: ui-fundament.
 */
import { takeCodeFromLocation } from './auth';

export const startCode: string | null = typeof window === 'undefined' ? null : takeCodeFromLocation();
