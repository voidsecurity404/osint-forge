<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { screenshotURL } from "../lib/api";
  import type { graph } from "../lib/models";

  const shots = $derived.by<graph.Node[]>(() => {
    app.version;
    return (app.view ? app.view.allNodes() : []).filter((n) => typeof n.props?.screenshot === "string");
  });
  function open(n: graph.Node) {
    app.mode = "graph";
    queueMicrotask(() => (app.selected = app.view?.focusNode(n.id) ?? n));
  }
</script>

<div class="gallery">
  {#if shots.length === 0}
    <p class="muted center">Скриншотов нет. Включите в настройках «Скриншоты живых веб-хостов» (нужен Chromium или Firefox) и выполните активное сканирование.</p>
  {:else}
    <div class="shots-grid">
      {#each shots as n (n.id)}
        <button class="shot-card" onclick={() => open(n)}>
          <img src={screenshotURL(String(n.props!.screenshot))} alt={n.label} loading="lazy" />
          <div class="shot-label">{n.label}</div>
        </button>
      {/each}
    </div>
  {/if}
</div>
