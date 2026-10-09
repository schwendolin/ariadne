<script lang="ts">
  import type { LogLine } from '../api/types';
  import { segments } from './logsegments';

  let { line, marked = false, showHidden = false }: { line: LogLine; marked?: boolean; showHidden?: boolean } = $props();
  const segs = $derived(segments(line, showHidden));
</script>

<div class="line" class:marked class:echo={line.prompt_echo} class:overwritten={line.overwritten}>
  <span class="ln">{line.n + 1}</span><span class="tx">{#each segs as s, i (i)}<span class={s.classes}>{s.text}</span>{/each}</span>
</div>

<style>
  .line {
    display: flex;
    font-family: var(--font-mono);
    font-size: 12.5px;
    line-height: 20px;
    white-space: pre;
    color: var(--log-text);
  }
  .marked {
    background: var(--mark-bg);
    box-shadow: inset 3px 0 0 var(--mark-border);
  }
  .echo {
    opacity: 0.55;
  }
  .overwritten .tx {
    text-decoration: line-through dotted;
  }
  .ln {
    flex: none;
    width: 5ch;
    padding-right: 1ch;
    text-align: right;
    color: var(--text-muted);
    user-select: none;
  }
  .tx {
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .tx :global(.fg-black) { color: var(--sgr-black); }
  .tx :global(.fg-red) { color: var(--sgr-red); }
  .tx :global(.fg-green) { color: var(--sgr-green); }
  .tx :global(.fg-yellow) { color: var(--sgr-yellow); }
  .tx :global(.fg-blue) { color: var(--sgr-blue); }
  .tx :global(.fg-magenta) { color: var(--sgr-magenta); }
  .tx :global(.fg-cyan) { color: var(--sgr-cyan); }
  .tx :global(.fg-white) { color: var(--sgr-white); }
  .tx :global(.bg-yellow) { background: var(--sgr-bg-yellow); }
  .tx :global(.bg-red) { background: var(--sgr-bg-red); }
  .tx :global(.b) { font-weight: 700; }
  .tx :global(.masked) { color: var(--text-muted); font-style: italic; }
  .tx :global(.concealed) { outline: 1px dashed var(--target-underline); }
</style>
