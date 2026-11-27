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
    if (!confirm("Bu scan tarixdan o'chirilsinmi?")) return;
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
    <h2>🕓 Scan tarixi</h2>
    <button class="ghost sm" onclick={() => (app.drawer = null)} aria-label="Yopish">✕</button>
  </div>
  {#if loading && targets.length === 0}
    <p class="muted">Yuklanmoqda…</p>
  {:else if targets.length === 0}
    <p class="muted">Hali saqlangan scan yo'q. Har bir tugagan scan shu yerga avtomatik saqlanadi.</p>
  {/if}
  <ul class="hist">
    {#each targets as t (t.target)}
      <li>
        <button class="hist-target" class:open={expanded === t.target} onclick={() => expand(t.target)}>
          <span class="name">{t.target}</span>
          <span class="meta">{t.scans} ta · {when(t.last)}</span>
        </button>
        {#if expanded === t.target}
          <ul class="hist-scans">
            {#each scans as s, i (s.id)}
              <li>
                <div class="scan-line">
                  <span class="when">{when(s.when)}</span>
                  <span class="meta">{s.nodes} tugun · {s.findings} topilma</span>
                </div>
                <div class="scan-actions">
                  <button class="ghost sm" onclick={() => openScan(t.target, s.id)} disabled={app.running}>📂 Ochish</button>
                  {#if i < scans.length - 1}
                    <button class="ghost sm" onclick={() => compareScans(t.target, scans[i + 1].id, s.id)} disabled={app.running} title="Oldingi scan bilan solishtirish">🔁 Diff</button>
                  {/if}
                  <button class="ghost sm danger-text" onclick={() => del(t.target, s.id)} title="O'chirish">🗑</button>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </li>
    {/each}
  </ul>
</aside>
