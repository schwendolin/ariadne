/**
 * Karte, «Als Nächstes» und Host-Detail gegen den Mock-Build unter der Daemon-CSP (Besitzer:
 * ui-karte). Cytoscape mit fcose läuft echt (Canvas, Kanten, Faden), die Host-Karten sind HTML.
 * fixtures.ts prüft nach jedem Test: keine CSP-Verletzung, kein Seitenfehler, kein <style>-Element
 * mit Inhalt.
 */
import type { Locator, Page } from '@playwright/test';
import { expect, openMock, test } from '../fixtures';

const H101 = 'ip:default/192.168.56.101';
const H103 = 'ip:default/192.168.56.103';
const H104 = 'ip:default/192.168.56.104';

const card = (page: Page, id: string): Locator => page.locator(`[data-map-card][data-host-id="${id}"]`);
const column = (page: Page): Locator => page.locator('aside.column');

/** wartet, bis Cytoscape gezeichnet und die Lage berechnet ist */
async function mapReady(page: Page): Promise<void> {
  await expect(page.locator('.canvas .cy canvas').first()).toBeAttached();
  await expect(card(page, H101)).toBeVisible();
  await expect(page.locator('.marker')).toHaveCount(2);
}

test.describe('Karte', () => {
  test('Hauptansicht: Cytoscape mit Kanten, HTML-Karten, Faden 1 und 2, Segment, Lagebild, Out of Scope', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await expect(page.locator('.lage .sum')).toHaveText(/^Stand \d\d:\d\d · 3 Hosts, 1 im Nebel · 1 mit Zugriff$/);
    await expect(page.getByRole('button', { name: /^\+3 seit \d\d:\d\d$/ })).toBeVisible();
    await expect(page.locator('.seg-label')).toHaveText('192.168.56.0/24');
    await expect(page.locator('.marker')).toHaveText(['1', '2']);
    await expect(card(page, 'kali')).toContainText('192.168.56.102');
    await expect(card(page, H101)).toContainText('23 Services');
    await expect(card(page, H103)).toContainText('im Nebel');
    await expect(card(page, H104)).toContainText('Sackgasse · nur RDP');
    await expect(page.getByRole('button', { name: 'Out of Scope · 4' })).toBeVisible();
    // verknüpfter Host der gewählten Klärung K1 (Kontextvorschlag → .101)
    await expect(card(page, H101).locator('xpath=..').locator('.ring-label')).toHaveText('K1');
    // Karten liegen im sichtbaren Bereich der Karte, nicht übereinander
    const boxes = await Promise.all([H101, H103, H104, 'kali'].map((id) => card(page, id).boundingBox()));
    const map = await page.locator('section.map').boundingBox();
    for (const b of boxes) {
      expect(b && map && b.x >= map.x && b.x + b.width <= map.x + map.width - 38 && b.y >= map.y + 40 && b.y + b.height <= map.y + map.height).toBe(true);
    }
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i];
        const c = boxes[j];
        const overlap = a && c && a.x < c.x + c.width && c.x < a.x + a.width && a.y < c.y + c.height && c.y < a.y + a.height;
        expect(overlap, `Karten ${i} und ${j} überlappen`).toBeFalsy();
      }
    }
    // Spalte 27 %, 320 bis 480 px
    const col = await column(page).boundingBox();
    expect(Math.round(col?.width ?? 0)).toBe(Math.round(1440 * 0.27));
  });

  test('«+3 seit» lässt das Neue einmal pulsieren (bei reduzierter Bewegung statischer Ring)', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await openMock(page, 'normal');
    await mapReady(page);
    await page.getByRole('button', { name: /^\+3 seit/ }).click();
    await expect(card(page, H101).locator('xpath=..')).toHaveClass(/pulse-static/);
    await expect(page.locator('.marker').first()).toHaveClass(/pulse-static/);
    await expect(card(page, H104).locator('xpath=..')).not.toHaveClass(/pulse-static/);
  });

  test('Host wählen öffnet das Detail mit Auswahlring; Esc kehrt zurück, der Fokus geht auf den Host', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await card(page, H101).click();
    await expect(page).toHaveURL(/host=ip%3Adefault%2F192\.168\.56\.101/);
    await expect(column(page).getByRole('heading', { name: '192.168.56.101' })).toBeVisible();
    await expect(column(page)).toContainText('root, per Entscheid');
    await expect(column(page)).toContainText('! Injection-Verdacht · vom Ziel angeboten');
    await expect(card(page, H101).locator('xpath=..').locator('.ring-sel')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page).not.toHaveURL(/host=/);
    await expect(column(page).getByRole('heading', { name: 'Als Nächstes' })).toBeVisible();
    await expect(card(page, H101)).toBeFocused();
    // Klick ins Leere schliesst das Detail ebenso
    await card(page, H104).click();
    await expect(page).toHaveURL(/host=/);
    const map = await page.locator('section.map').boundingBox();
    await page.mouse.click((map?.x ?? 0) + 120, (map?.y ?? 0) + (map?.height ?? 0) - 120);
    await expect(page).not.toHaveURL(/host=/);
  });

  test('Tab erreicht die Hosts, Pfeiltasten springen zum nächstgelegenen in der Richtung', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await card(page, 'kali').focus();
    const at = async () => page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.hostId ?? null);
    const pos = async (id: string) => {
      const b = await card(page, id).boundingBox();
      return { x: (b?.x ?? 0) + (b?.width ?? 0) / 2, y: (b?.y ?? 0) + (b?.height ?? 0) / 2 };
    };
    const kali = await pos('kali');
    await page.keyboard.press('ArrowRight');
    const first = await at();
    expect(first).not.toBe('kali');
    expect((await pos(first ?? '')).x).toBeGreaterThan(kali.x);
    await page.keyboard.press('ArrowLeft');
    expect(await at()).not.toBe(first);
    // Tab geht von Karte zu Karte (HTML-Overlay, keine Leinwand im Tab-Weg)
    await card(page, 'kali').focus();
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => document.activeElement?.hasAttribute('data-map-card'))).toBe(true);
    // Enter auf einer Karte öffnet das Detail
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/host=/);
  });

  test('+ − 0 zoomen und passen ein (50 bis 140 %), Ziehen verschiebt einen Host', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    const zoom = () => page.locator('.layer').evaluate((el) => Number((el as HTMLElement).style.getPropertyValue('--zoom')));
    const z0 = await zoom();
    expect(z0).toBeGreaterThanOrEqual(0.5);
    expect(z0).toBeLessThanOrEqual(1.4);
    await page.locator('section.map').hover();
    await page.keyboard.press('+');
    await expect.poll(zoom).toBeGreaterThan(z0);
    await page.keyboard.press('-');
    await page.keyboard.press('-');
    await expect.poll(zoom).toBeLessThan(z0);
    await page.keyboard.press('0');
    await expect.poll(zoom).toBeCloseTo(z0, 1);
    const before = await card(page, H104).boundingBox();
    await page.mouse.move((before?.x ?? 0) + 60, (before?.y ?? 0) + 20);
    await page.mouse.down();
    await page.mouse.move((before?.x ?? 0) + 120, (before?.y ?? 0) - 40, { steps: 6 });
    await page.mouse.up();
    const after = await card(page, H104).boundingBox();
    expect(Math.round((after?.x ?? 0) - (before?.x ?? 0))).toBeGreaterThan(40);
    // Ziehen ist kein Klick: das Detail bleibt zu
    await expect(page).not.toHaveURL(/host=/);
  });

  test('Ebenen und Legende: Nebel und Faden aus, Auswahl in der URL; Out-of-Scope-Popover', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await page.getByRole('button', { name: 'Ebenen und Legende' }).click();
    const pop = page.getByRole('dialog', { name: 'Ebenen und Legende' });
    await expect(pop).toContainText('Credentials');
    await pop.getByLabel('Nebel').uncheck();
    await expect(page).toHaveURL(/ebenen=services%2Cthread%2Coos/);
    await expect(card(page, H103)).toHaveCount(0);
    await pop.getByLabel('Faden').uncheck();
    await expect(page.locator('.marker')).toHaveCount(0);
    await page.keyboard.press('Escape');
    await page.reload();
    await expect(card(page, H101)).toBeVisible();
    await expect(card(page, H103)).toHaveCount(0);
    await page.getByRole('button', { name: 'Out of Scope · 4' }).click();
    const oos = page.getByRole('dialog', { name: 'Out of Scope' });
    await expect(oos).toContainText('fd00:56::101');
    await expect(oos).toContainText('gleiche MAC wie .101');
    await expect(oos).toContainText('Scope erweitern geht in v0.1 nur im Terminal.');
  });

  test('t schaltet zur Host-Tabelle und zurück; j und ↵ öffnen das Detail', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await page.locator('body').click({ position: { x: 5, y: 880 } });
    await page.keyboard.press('t');
    await expect(page).toHaveURL(/ansicht=tabelle/);
    const rows = page.locator('.table-view button.row');
    await expect(rows).toHaveCount(3);
    // Reihenfolge: Konflikte, dann Fortschritt, dann Adresse (.101 Zugriff, .104 Sackgasse, .103 Nebel)
    await expect(rows.nth(0)).toHaveAttribute('data-host-id', H101);
    await expect(rows.nth(1)).toHaveAttribute('data-host-id', H104);
    await page.keyboard.press('j');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/host=ip%3Adefault%2F192\.168\.56\.104/);
    await expect(column(page).locator('.detail')).toContainText('192.168.56.104');
    await page.keyboard.press('Escape');
    await expect(rows.nth(1)).toBeFocused();
    await page.keyboard.press('t');
    await expect(page).not.toHaveURL(/ansicht=/);
    await expect(card(page, H101)).toBeVisible();
  });

  test('ab 200 Hosts nur die Tabelle, Konflikte zuerst, Umschalter Services', async ({ page }) => {
    await openMock(page, 'many');
    const rows = page.locator('.table-view button.row');
    await expect(rows.first()).toContainText('192.168.56.17');
    await expect(rows.first()).toContainText('! Konflikt: Dienstname 445');
    await expect(page.locator('.table-view .foot')).toHaveText(/^1 bis \d+ von 250 · j k wechseln · ↵ Host-Detail$/);
    await expect(page.locator('[data-map-card]')).toHaveCount(0);
    await page.getByRole('radio', { name: 'Services' }).click();
    await expect(page).toHaveURL(/tabelle=services/);
    await expect(page.getByRole('radio', { name: 'Credentials · v0.2' })).toBeDisabled();
  });
});

test.describe('Als Nächstes', () => {
  test('K2 übernehmen (a), K3 zusammenführen (a): Ruhezustand mit Cursor auf dem ersten Denkanstoss', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    const col = column(page);
    await expect(col.locator('.card')).toContainText('T3 «listener» · Reverse Shell');
    await expect(col.locator('.keys')).toHaveText('j k wechseln · a übernehmen · ↵ Beleg · ? Hilfe');
    await page.keyboard.press('a');
    await expect(col.locator('.done')).toContainText('Kontext T3 = .101, rückwirkend');
    await expect(col.locator('.card')).toContainText('Zusammenführen?');
    await expect(col.locator('.card')).toContainText('Gleiche MAC-Adresse 08:00:27:63:7e:e7');
    await page.keyboard.press('a');
    await expect(col.locator('.done')).toHaveCount(2);
    await expect(col.locator('.done').nth(1)).toContainText('fd00:56::101 mit .101 zusammengeführt');
    await expect(col.locator('.group-head').first()).toContainText('erledigt');
    await expect(col.locator('.card')).toContainText('Prüfziel · Regel R-ANON-ZUGRIFF');
    await expect(col.locator('.keys')).toHaveText('j k wechseln · ↵ Beleg · ? Hilfe');
    await expect(page.locator('.ring-label')).toHaveCount(0);
    // Rückgängig (u) holt K3 zurück
    await page.keyboard.press('u');
    await expect(col.locator('button.line[data-item-key^="merge:"], .card[data-item-key^="merge:"]')).toHaveCount(1);
    await expect(col.locator('.done')).toHaveCount(1);
  });

  test('Denkanstoss: Lernstufen, Vorlage mit «Kopieren · Mac», Erledigt und Verwerfen; KI gesperrt mit Grund', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await openMock(page, 'calm');
    const col = column(page);
    await expect(col).toContainText('Nichts zu klären.');
    const sug = col.locator('.card');
    await sug.getByRole('button', { name: /1 Frage zeigen/ }).click();
    await expect(sug).toContainText('Welche Daten gibt dieser Dienst ohne Anmeldung preis?');
    await sug.getByRole('button', { name: /2 Richtung zeigen/ }).click();
    await sug.getByRole('button', { name: /3 Vorlage zeigen/ }).click();
    await expect(sug.locator('.tpl code').first()).toHaveText('nmap -p 21 --script ftp-anon 192.168.56.101');
    await sug.getByRole('button', { name: 'Kopieren · Mac' }).first().click();
    await expect(sug).toContainText('In der Zwischenablage des Macs');
    // eslint-disable-next-line no-restricted-properties -- der Test liest die Zwischenablage nur aus
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('nmap -p 21 --script ftp-anon 192.168.56.101');
    await expect(col.getByRole('button', { name: /ausführen/i })).toHaveCount(0);
    const ai = col.getByRole('button', { name: /Denkanstoss anfordern \(KI\)/ });
    await expect(ai).toBeDisabled();
    await expect(ai).toHaveAttribute('title', /späteren Version/);
    await sug.getByRole('button', { name: 'Erledigt' }).click();
    await expect(col.locator('.done').first()).toContainText('Unauthentisierten Zugriff');
    await expect(col.locator('.card')).toContainText('Version recherchieren');
    await col.locator('.card').getByRole('button', { name: 'Verwerfen' }).click();
    await expect(col.locator('.done.s-dismissed .strike')).toContainText('Version recherchieren');
  });

  test('j k wechseln, n springt zum nächsten Denkanstoss, ↵ öffnet die Belegansicht', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await page.keyboard.press('j');
    await expect(column(page).locator('.card')).toContainText('Zusammenführen?');
    await page.keyboard.press('n');
    await expect(column(page).locator('.card')).toContainText('R-ANON-ZUGRIFF');
    await page.keyboard.press('k');
    await page.keyboard.press('k');
    await expect(column(page).locator('.card')).toContainText('Kontext klären');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/beleg=c%3A[0-9a-f]{64}/);
  });

  test('Anderer Host … öffnet den Kontext-Dialog (ui-verlauf)', async ({ page }) => {
    await openMock(page, 'normal');
    await mapReady(page);
    await column(page).getByRole('button', { name: 'Anderer Host …' }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
  });

  test('feindliche Werte: Vorlage mit Shell-Sonderzeichen nur als Einzelwerte, nichts davon als HTML', async ({ page }) => {
    await openMock(page, 'hostile', '/karte?tafel=einstellungen');
    await page.getByRole('switch', { name: 'Lernmodus' }).click();
    await page.keyboard.press('Escape');
    await mapReady(page);
    await page.keyboard.press('n');
    const sug = column(page).locator('.card');
    await expect(sug).toContainText("vsftpd'; !sh -c 'id");
    await expect(sug).toContainText('! Enthält Shell-Sonderzeichen. Keine fertige Vorlage.');
    await expect(sug.locator('.tpl')).toHaveCount(0);
    await expect(sug.getByRole('button', { name: 'Mac' })).toHaveCount(2);
    await page.getByRole('button', { name: 'Out of Scope · 4' }).click();
    await expect(page.getByRole('dialog', { name: 'Out of Scope' })).toContainText('<img src=x onerror=alert(1)>.lame.htb');
    expect(await page.locator('main img, main script, main iframe, main a[href]').count()).toBe(0);
  });
});
