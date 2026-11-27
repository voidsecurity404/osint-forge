<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { STATUS_CLASSES } from "../lib/graph";

  const items = $derived(STATUS_CLASSES.filter((c) => app.statusCounts[c.key]));

  function toggle(key: string) {
    app.statusFilter = app.statusFilter === key ? null : key;
    app.selected = null;
    app.view?.highlightStatus(app.statusFilter);
  }
</script>

{#if items.length > 0 && app.mode === "graph"}
  <div class="status-legend" class:shifted={!!app.selected} title="Цвета по HTTP-статусам — нажмите, чтобы выделить">
    <div class="legend-title">HTTP-статус</div>
    {#each items as c}
      <button
        class="legend-item"
        class:active={app.statusFilter === c.key}
        class:faded={app.statusFilter !== null && app.statusFilter !== c.key}
        title={c.hint}
        onclick={(e) => { e.stopPropagation(); toggle(c.key); }}
      >
        <span class="legend-dot" style="background:{c.color}"></span>
        <span class="legend-label">{c.label}</span>
        <span class="legend-count">{app.statusCounts[c.key]}</span>
      </button>
    {/each}
  </div>
{/if}
