<script lang="ts">
  import { app, errMsg } from "../lib/state.svelte";
  import { HistoryTargets, HistoryList, HistoryDelete, type HistoryTarget, type HistoryEntry } from "../lib/api";
  import { compareScans, openScan, when } from "../lib/actions";

  let targets = $state<HistoryTarget[]>([]);
  let expanded = $state<string | null>(null);
  let scans = $state<HistoryEntry[]>([]);
  let loading = $state(false);

  async function load() {
    loading = true;
    try {
      targets = await HistoryTargets();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    } finally {
      loading = false;
    }
  }
  async function expand(t: string) {
    if (expanded === t) {
      expanded = null;
      return;
    }
    expanded = t;
    scans = [];
    try {
      scans = await HistoryList(t);
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
  async function del(t: string, id: string) {
    if (!confirm("Удалить это сканирование из истории?")) return;
    try {
      await HistoryDelete(t, id);
      scans = scans.filter((s) => s.id !== id);
      load();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }

  // Reload whenever the drawer opens or a scan finishes.
  $effect(() => {
    app.running;
    load();
  });
</script>

<aside class="drawer">
  <div class="drawer-head">
    <h2>🕓 История сканирований</h2>
    <button class="ghost sm" onclick={() => (app.drawer = null)} aria-label="Закрыть">✕</button>
  </div>
  {#if loading && targets.length === 0}
    <p class="muted">Загрузка…</p>
  {:else if targets.length === 0}
    <p class="muted">Сохранённых сканирований пока нет. Каждое завершённое сканирование сохраняется сюда автоматически.</p>
  {/if}
  <ul class="hist">
    {#each targets as t (t.target)}
      <li>
        <button class="hist-target" class:open={expanded === t.target} onclick={() => expand(t.target)}>
          <span class="name">{t.target}</span>
          <span class="meta">сканирований: {t.scans} · {when(t.last)}</span>
        </button>
        {#if expanded === t.target}
          <ul class="hist-scans">
            {#each scans as s, i (s.id)}
              <li>
                <div class="scan-line">
                  <span class="when">{when(s.when)}</span>
                  <span class="meta">узлов: {s.nodes} · находок: {s.findings}</span>
                </div>
                <div class="scan-actions">
                  <button class="ghost sm" onclick={() => openScan(t.target, s.id)} disabled={app.running}>📂 Открыть</button>
                  {#if i < scans.length - 1}
                    <button class="ghost sm" onclick={() => compareScans(t.target, scans[i + 1].id, s.id)} disabled={app.running} title="Сравнить с предыдущим сканированием">🔁 Сравнить</button>
                  {/if}
                  <button class="ghost sm danger-text" onclick={() => del(t.target, s.id)} title="Удалить">🗑</button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </li>
    {/each}
  </ul>
</aside>
