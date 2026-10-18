<!--
  Logo-Zeichen 2c (README «Logo»): gleichseitiges Dreieck aus drei gefüllten Knoten, offene Basis,
  Kante vom Knoten unten rechts zur Mitte des linken Schenkels. Immer einfarbig in --fg
  (currentColor). Inline-SVG ohne style-Attribut. Besitzer: ui-fundament.
-->
<script lang="ts">
  let { size = 20, label = 'ARIADNE', decorative = false }: { size?: number; label?: string; decorative?: boolean } = $props();
</script>

<svg
  class="mark"
  width={size}
  height={size}
  viewBox="0 0 32 32"
  fill="none"
  stroke="currentColor"
  stroke-width="3"
  stroke-linecap="round"
  role={decorative ? undefined : 'img'}
  aria-label={decorative ? undefined : label}
  aria-hidden={decorative ? 'true' : undefined}
>
  <path d="M16 6.5 L5 25.55 M16 6.5 L27 25.55 M27 25.55 L10.5 16.03"></path>
  <circle cx="16" cy="6.5" r="3.6" fill="currentColor" stroke="none"></circle>
  <circle cx="5" cy="25.55" r="3.6" fill="currentColor" stroke="none"></circle>
  <circle cx="27" cy="25.55" r="3.6" fill="currentColor" stroke="none"></circle>
</svg>

<style>
  .mark {
    display: block;
    flex: none;
    color: var(--fg);
  }
</style>
