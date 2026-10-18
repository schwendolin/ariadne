<!--
  Rückgängig pro Befehl inline in der Zeitachsenzeile (Screen 6): «Werte aus diesem Befehl
  verwerfen?», Erklärung, Grund (optional), «Rückgängig machen» (d.unit.distrust, allein) und
  «Abbrechen»; Rückmeldung «18 verworfen, 0 geschwächt» mit «Wieder vertrauen» (d.revoke).
  Besitzer: ui-verlauf. Gerüst aus Phase 1.
-->
<script lang="ts">
  let { cmdId }: { cmdId: string; onclose: () => void } = $props();
</script>

<div class="undo" data-cmd-id={cmdId}></div>
