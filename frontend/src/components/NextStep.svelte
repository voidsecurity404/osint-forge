<script lang="ts">
  import { guideFor, SCOPE } from "../lib/guidance";
  import type { graph } from "../lib/models";

  let { node }: { node: graph.Node } = $props();
  const guide = $derived(guideFor(node));
  let open = $state(true);
</script>

{#if guide}
  <div class="nextstep">
    <button class="ns-head" onclick={() => (open = !open)}>
      <span>🎯 Следующий шаг — {guide.title}</span>
      <span class="chev">{open ? "▾" : "▸"}</span>
    </button>
    {#if open}
      <div class="ns-body">
        <p class="ns-why">{guide.why}</p>
        <div class="ns-sub">Проверить вручную:</div>
        <ul class="ns-list">
          {#each guide.checks as c}<li>{c}</li>{/each}
        </ul>
        {#if guide.tools?.length}
          <div class="ns-sub">Инструменты:</div>
          <div class="ns-tools">
            {#each guide.tools as t}<code>{t}</code>{/each}
          </div>
        {/if}
        <p class="ns-warn">⚠️ {SCOPE}</p>
      </div>
    {/if}
  </div>
{/if}
