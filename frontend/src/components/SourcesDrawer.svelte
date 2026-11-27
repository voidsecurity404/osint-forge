<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { stageName } from "../lib/i18n";

  // Group by stage, preserving first-seen order.
  const stages = $derived.by(() => {
    const order: string[] = [];
    const map: Record<string, typeof app.timings> = {};
    for (const t of app.timings) {
      if (!map[t.stage]) {
        map[t.stage] = [];
        order.push(t.stage);
      }
      map[t.stage].push(t);
    }
    return order.map((s) => ({ stage: s, items: map[s] }));
  });
  const totalMs = $derived(app.timings.reduce((a, t) => a + (t.durationMs || 0), 0));

  function ms(n: number): string {
    if (!n) return "—";
    return n >= 1000 ? (n / 1000).toFixed(1) + "s" : n + "ms";
  }
  const icon: Record<string, string> = { running: "⏳", done: "✅", error: "❌", skipped: "⏭" };
</script>

<aside class="drawer">
  <div class="drawer-head">
    <h2>⚙️ Источники</h2>
    <button class="ghost sm" onclick={() => (app.drawer = null)} aria-label="Закрыть">✕</button>
  </div>
  {#if app.timings.length === 0}
    <p class="muted sm">Когда начнётся сканирование, здесь будет видно, сколько времени занял каждый источник (dns, nmap, fuzz…) и сколько элементов он нашёл.</p>
  {:else}
    <p class="muted sm">Суммарное время работы: {ms(totalMs)} (внутри этапа источники работают параллельно).</p>
    {#each stages as g}
      <div class="src-stage">{stageName(g.stage)}</div>
      <ul class="src-list">
        {#each g.items as t (t.name)}
          <li>
            <span class="src-ico">{icon[t.status] ?? "•"}</span>
            <span class="src-name" title={t.error ?? ""}>{t.name}</span>
            <span class="src-add">+{t.nodes} уз.</span>
            <span class="src-ms">{ms(t.durationMs)}</span>
          </li>
          {#if t.error}<li class="src-err">{t.error}</li>{/if}
        {/each}
      </ul>
    {/each}
  {/if}
</aside>
