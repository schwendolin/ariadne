/**
 * Farbgrammatik der Karte (Architektur 7.5) als Cytoscape-Stylesheet.
 *
 * Die Farben kommen aus den Theme-Tokens (--map-* in src/theme/tokens.css) und
 * werden zur Laufzeit gelesen; bei einem Theme-Wechsel baut die Karte das
 * Stylesheet neu. Cytoscape zeichnet auf Canvas: Beschriftungen sind immer
 * Text, nie HTML.
 */
import type { StylesheetJson } from 'cytoscape';

export const MAP_TOKENS = [
  'bg', 'label', 'label-muted', 'label-bg', 'kali-fill', 'kali-border', 'segment-fill', 'segment-border', 'fog-fill',
  'fog-border', 'discovered', 'scanned', 'versions', 'user', 'admin', 'border', 'in-progress', 'dead-end', 'done', 'thread',
  'thread-label', 'conflict', 'ai', 'oos-fill', 'oos-hatch', 'oos-border', 'service-fill', 'service-border', 'reach',
  'selected', 'fresh',
] as const;
export type MapToken = (typeof MAP_TOKENS)[number];
export type MapTheme = Record<MapToken, string> & { font: string };

const FALLBACK = '#888888';
const COLOR = /^(#[0-9a-fA-F]{3,8}|rgba?\([\d\s.,%]+\)|hsla?\([\d\s.,%deg]+\))$/;

/** Liest die Karten-Tokens aus den berechneten Styles. Ungültige Werte werden grau. */
export function readMapTheme(root: Element = document.documentElement): MapTheme {
  const cs = getComputedStyle(root);
  const theme = {} as MapTheme;
  for (const k of MAP_TOKENS) {
    const v = cs.getPropertyValue(`--map-${k}`).trim();
    theme[k] = COLOR.test(v) ? v : FALLBACK;
  }
  const font = getComputedStyle(document.body).fontFamily || 'sans-serif';
  theme.font = font;
  return theme;
}

export function buildStyle(th: MapTheme, hatchUrl: string | null): StylesheetJson {
  return [
    {
      selector: 'node',
      style: {
        label: 'data(label)',
        'font-family': th.font,
        'font-size': 11,
        color: th.label,
        'text-wrap': 'wrap',
        'text-max-width': '170px',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 5,
        'text-background-color': th['label-bg'],
        'text-background-opacity': 0.85,
        'text-background-padding': '2px',
        'text-background-shape': 'roundrectangle',
        'min-zoomed-font-size': 6,
      },
    },
    {
      selector: 'node.kali',
      style: {
        shape: 'hexagon',
        width: 38,
        height: 38,
        'background-color': th['kali-fill'],
        'border-color': th['kali-border'],
        'border-width': 2,
        'font-weight': 'bold',
      },
    },
    {
      selector: 'node.segment',
      style: {
        shape: 'round-rectangle',
        'background-color': th['segment-fill'],
        'background-opacity': 1,
        'border-color': th['segment-border'],
        'border-style': 'dashed',
        'border-width': 1.5,
        'text-valign': 'top',
        'text-halign': 'center',
        'text-margin-y': -4,
        'font-weight': 'bold',
        color: th['label-muted'],
        'text-background-opacity': 0,
        padding: '22px',
      },
    },
    {
      selector: 'node.host',
      style: {
        shape: 'round-rectangle',
        width: 34,
        height: 34,
        'background-color': th.discovered,
        'border-color': th.border,
        'border-width': 1.5,
        'border-style': 'solid',
      },
    },
    { selector: 'node.host.p1', style: { 'background-color': th.discovered } },
    { selector: 'node.host.p2', style: { 'background-color': th.scanned } },
    { selector: 'node.host.p3', style: { 'background-color': th.versions } },
    { selector: 'node.host.p4', style: { 'background-color': th.user, width: 38, height: 38 } },
    { selector: 'node.host.p5', style: { 'background-color': th.admin, width: 40, height: 40 } },
    { selector: 'node.work-in_progress', style: { 'border-color': th['in-progress'], 'border-width': 4 } },
    { selector: 'node.work-dead_end', style: { 'border-color': th['dead-end'], 'border-style': 'dashed', 'border-width': 3 } },
    { selector: 'node.work-done', style: { 'border-color': th.done, 'border-style': 'double', 'border-width': 6 } },
    {
      selector: 'node.fog',
      style: {
        'background-color': th['fog-fill'],
        'background-opacity': 0.7,
        'border-color': th['fog-border'],
        'border-style': 'dotted',
        'border-width': 2,
        color: th['label-muted'],
      },
    },
    {
      selector: 'node.service',
      style: {
        shape: 'ellipse',
        width: 14,
        height: 14,
        'background-color': th['service-fill'],
        'border-color': th['service-border'],
        'border-width': 1.5,
        'font-size': 9,
        color: th['label-muted'],
        'text-max-width': '130px',
      },
    },
    { selector: 'node.service.fog', style: { 'border-style': 'dotted', 'background-opacity': 0.5 } },
    { selector: 'node.service.work-done', style: { 'border-color': th.done, 'border-width': 2.5, 'border-style': 'solid' } },
    {
      selector: 'node.conflict',
      style: { 'underlay-color': th.conflict, 'underlay-opacity': 0.45, 'underlay-padding': 7, 'underlay-shape': 'round-rectangle' },
    },
    {
      selector: 'node.oos',
      style: {
        shape: 'round-rectangle',
        width: 132,
        height: 48,
        'background-color': th['oos-fill'],
        ...(hatchUrl
          ? { 'background-image': hatchUrl, 'background-repeat': 'repeat', 'background-width': '12px', 'background-height': '12px', 'background-image-crossorigin': 'null' }
          : {}),
        'border-color': th['oos-border'],
        'border-style': 'dashed',
        'border-width': 1.5,
        'text-valign': 'center',
        'text-margin-y': 0,
        'font-size': 10.5,
      },
    },
    { selector: 'node.fresh', style: { 'border-color': th.fresh, 'border-width': 3 } },
    { selector: 'node.pulse', style: { 'overlay-color': th.fresh, 'overlay-opacity': 0.3, 'overlay-padding': 10 } },
    { selector: 'node.highlight', style: { 'overlay-color': th.fresh, 'overlay-opacity': 0.22, 'overlay-padding': 9 } },
    { selector: 'node:selected', style: { 'overlay-color': th.selected, 'overlay-opacity': 0.18, 'overlay-padding': 8 } },
    {
      selector: 'edge',
      style: { width: 1.2, 'line-color': th.reach, 'curve-style': 'bezier', 'target-arrow-shape': 'none' },
    },
    { selector: 'edge.reach', style: { 'line-style': 'dashed', 'line-dash-pattern': [6, 4], width: 1.5 } },
    { selector: 'edge.svc', style: { width: 1, 'line-color': th['service-border'], 'curve-style': 'straight' } },
    {
      selector: 'edge.thread',
      style: {
        width: 4.5,
        'line-color': th.thread,
        'target-arrow-shape': 'triangle',
        'target-arrow-color': th.thread,
        'arrow-scale': 1.1,
        label: 'data(label)',
        'font-family': th.font,
        'font-size': 10,
        'font-weight': 'bold',
        color: th['thread-label'],
        'text-background-color': th.thread,
        'text-background-opacity': 1,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
        'text-rotation': 'none',
        'z-index': 20,
        'loop-direction': '-40deg',
        'loop-sweep': '-70deg',
        'control-point-step-size': 60,
      },
    },
    { selector: 'edge:selected', style: { 'overlay-color': th.selected, 'overlay-opacity': 0.2 } },
  ];
}

/** Schraffur für Out-of-Scope als PNG-Blob (keine data:-URL, die CSP erlaubt nur blob:). */
export function hatchPattern(fill: string, hatch: string): Promise<string | null> {
  if (typeof document === 'undefined') return Promise.resolve(null);
  const canvas = document.createElement('canvas');
  canvas.width = 12;
  canvas.height = 12;
  const ctx = canvas.getContext('2d');
  if (!ctx) return Promise.resolve(null);
  ctx.fillStyle = fill;
  ctx.fillRect(0, 0, 12, 12);
  ctx.strokeStyle = hatch;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(-3, 3);
  ctx.lineTo(3, -3);
  ctx.moveTo(0, 12);
  ctx.lineTo(12, 0);
  ctx.moveTo(9, 15);
  ctx.lineTo(15, 9);
  ctx.stroke();
  return new Promise((resolve) => canvas.toBlob((b) => resolve(b ? URL.createObjectURL(b) : null), 'image/png'));
}
