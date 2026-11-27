<script lang="ts">
  import { onMount } from "svelte";
  import { GraphView } from "./lib/graph";
  import {
    StartScan,
    CancelScan,
    NmapInstalled,
    Export,
    type ExportFormat,
    Snapshot,
    Status,
    Timings,
    EventsOn,
    OnReconnect,
  } from "./lib/api";
  import type { core, graph } from "./lib/models";
  import { app, errMsg } from "./lib/state.svelte";
  import { compareScans, exitDiff } from "./lib/actions";
  import DetailPanel from "./components/DetailPanel.svelte";
  import SettingsModal from "./components/SettingsModal.svelte";
  import Footer from "./components/Footer.svelte";
  import Legend from "./components/Legend.svelte";
  import HistoryDrawer from "./components/HistoryDrawer.svelte";
  import MonitorDrawer from "./components/MonitorDrawer.svelte";
  import SourcesDrawer from "./components/SourcesDrawer.svelte";
  import TableView from "./components/TableView.svelte";
  import Gallery from "./components/Gallery.svelte";

  let graphEl: HTMLDivElement;
  let targetEl: HTMLInputElement;
  let showSettings = $state(false);
  let showExport = $state(false);
  let graphSearch = $state("");
  function runGraphSearch() {
    app.view?.search(graphSearch.trim());
  }

  // Delta coalescing buffer (plain, non-reactive).
  let pending: { nodes: any[]; edges: any[] } | null = null;
  let rafScheduled = false;
  let scanGen = 0; // bumped on every new scan; invalidates in-flight resyncs

  function flushPending() {
    const p = pending;
    pending = null;
    rafScheduled = false;
    if (p && app.view) app.view.apply(p as unknown as graph.Delta);
  }

  onMount(() => {
    const view = new GraphView(graphEl, (n) => (app.selected = n));
    app.view = view;
    view.onLayoutBusy = (b) => (app.layoutBusy = b);
    // Read-only diagnostics handle (layout quality checks from the console/E2E).
    (window as any).__osintForge = { view };
    view.onTap = () => (app.statusFilter = null); // any graph click replaces the status highlight
    NmapInstalled().then((v) => (app.nmapOk = v)).catch(() => {});
    targetEl?.focus();

    // Coalesce bursts of deltas into one apply per animation frame. A setTimeout
    // runs alongside the rAF as a fallback for hidden tabs (rAF paused).
    const doFlush = () => {
      if (!pending) return;
      try {
        flushPending();
        app.refreshCounts();
        if (app.running) view.fitDuringScan();
      } catch (err) {
        console.error("graph flush failed", err);
        rafScheduled = false;
      }
    };
    const offDelta = EventsOn("scan:delta", (d: graph.Delta) => {
      if (app.diff) return; // a diff view is on screen; the live graph resyncs on exit
      if (!pending) pending = { nodes: [], edges: [] };
      if (d.nodes) pending.nodes.push(...d.nodes);
      if (d.edges) pending.edges.push(...d.edges);
      if (!rafScheduled) {
        rafScheduled = true;
        requestAnimationFrame(doFlush);
        setTimeout(doFlush, 500);
      }
    });
    const offLog = EventsOn("scan:log", (l: core.LogLine) => {
      app.logs = [...app.logs.slice(-300), l];
    });
    const offProg = EventsOn("scan:progress", (p: core.Progress) => {
      app.progress = p;
      if (p.finished) {
        app.running = false;
        app.cancelling = false;
        flushPending();
        app.refreshCounts();
        view.finalize();
      }
    });
    // A scan started — by this tab, another tab or the monitor. The server has
    // already replaced its graph, so every tab starts from an empty view
    // (otherwise a monitor scan got merged on top of the old graph).
    const offStart = EventsOn("scan:start", (s: { target: string; monitor?: boolean }) => {
      scanGen++;
      pending = null;
      rafScheduled = false;
      app.diff = null;
      app.logs = [];
      app.selected = null;
      app.progress = null;
      app.timings = [];
      app.statusFilter = null;
      if (!app.running) app.target = s.target; // not started from this tab's input
      app.graphTarget = s.target;
      app.running = true;
      app.cancelling = false;
      view.reset();
      app.refreshCounts();
      app.loadNotes(s.target);
      if (s.monitor) app.flash("🔔 Monitoring skani boshlandi: " + s.target);
    });
    // The server graph was replaced (a stored scan was opened somewhere).
    const offReset = EventsOn("graph:reset", () => {
      if (!app.running && !app.diff) resync();
    });
    const offTiming = EventsOn("scan:timing", (t: any) => {
      const i = app.timings.findIndex((x) => x.name === t.name);
      if (i >= 0) app.timings[i] = t;
      else app.timings = [...app.timings, t];
    });

    // Full re-sync from the server: on SSE reconnect and when opened mid-scan.
    const resync = async () => {
      const gen = scanGen;
      try {
        const [snap, st, tm] = await Promise.all([Snapshot(), Status(), Timings()]);
        if (gen !== scanGen || app.diff) return; // stale, or a diff is on screen
        if (st.target && !app.target) app.target = st.target;
        app.graphTarget = st.target ?? "";
        app.running = st.running;
        if (!st.running) app.cancelling = false;
        app.timings = tm ?? [];
        // sync, not apply: drop what the server no longer has (its graph may
        // have been replaced while this tab was disconnected).
        pending = null;
        if (snap) view.sync(snap);
        app.selected = null;
        app.loadNotes();
        app.refreshCounts();
        if (!st.running) view.finalize();
      } catch {}
    };
    const offReconnect = OnReconnect(resync);
    resync();

    return () => {
      offReconnect();
      offDelta();
      offLog();
      offProg();
      offStart();
      offReset();
      offTiming();
      view.destroy();
    };
  });

  async function start() {
    app.error = "";
    if (!app.target.trim()) {
      app.error = "IP manzil yoki domen kiriting.";
      return;
    }
    scanGen++;
    app.diff = null;
    app.logs = [];
    app.selected = null;
    app.progress = null;
    app.timings = [];
    app.statusFilter = null;
    pending = null;
    rafScheduled = false;
    app.view?.reset();
    app.graphTarget = app.target.trim(); // refined by the server's scan:start
    app.notes = {};
    app.refreshCounts();
    app.running = true;
    app.cancelling = false;
    try {
      await StartScan(app.target.trim(), app.consent);
    } catch (e) {
      app.error = errMsg(e);
      app.running = false;
    }
  }

  // Cancelling is asynchronous: sources stop at their next check. The UI stays
  // in "stopping" until the server's final progress event (or, as a fallback,
  // /api/status) says the scan is over — flipping to idle immediately let the
  // user start a new scan that the server rejected as "already running".
  async function cancel() {
    if (app.cancelling) return;
    app.cancelling = true;
    try {
      await CancelScan();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
    const until = Date.now() + 30_000;
    while (app.cancelling && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 1000));
      try {
        if (!(await Status()).running) {
          app.running = false;
          app.cancelling = false;
        }
      } catch {}
    }
    app.cancelling = false;
  }

  async function doExport(format: ExportFormat) {
    showExport = false;
    try {
      const res = await Export(format, app.graphTarget || app.target.trim());
      if (res) app.flash("✅ " + res);
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }

  const EXPORTS: [ExportFormat, string][] = [
    ["html", "HTML"],
    ["md", "Markdown"],
    ["csv", "CSV"],
    ["sarif", "SARIF"],
    ["json", "JSON"],
    ["obsidian", "Obsidian vault (.zip)"],
  ];
</script>

<svelte:window onclick={() => (showExport = false)} />

<div class="app">
  <header>
    <div class="brand">🕸️ <span>osint-forge</span></div>
    <div class="controls">
      <input
        type="text"
        bind:this={targetEl}
        bind:value={app.target}
        placeholder="IP yoki domen kiriting — masalan 1.1.1.1 yoki example.com"
        onkeydown={(e) => e.key === "Enter" && !app.running && start()}
        disabled={app.running}
      />
      <label class="consent" title="Faqat o'zingizga tegishli yoki ruxsat berilgan nishonlarni skanerlang">
        <input type="checkbox" bind:checked={app.consent} disabled={app.running} />
        Aktiv skan — ruxsatim bor
      </label>
      {#if app.running}
        <button class="danger" onclick={cancel} disabled={app.cancelling}>{app.cancelling ? "To'xtatilmoqda…" : "To'xtatish"}</button>
      {:else}
        <button class="primary" onclick={start}>Skanlash</button>
      {/if}
      <div class="viewswitch">
        <button class:on={app.mode === "graph"} onclick={() => (app.mode = "graph")} title="Graf">🕸️</button>
        <button class:on={app.mode === "table"} onclick={() => (app.mode = "table")} title="Jadval">▦</button>
        <button class:on={app.mode === "gallery"} onclick={() => (app.mode = "gallery")} title="Skrinshotlar">🖼️</button>
      </div>
      <div class="dropdown">
        <button
          class="ghost"
          disabled={app.running}
          title="Hisobotni eksport qilish"
          onclick={(e) => {
            e.stopPropagation();
            showExport = !showExport;
          }}>⬇ Eksport ▾</button>
        {#if showExport}
          <div class="menu" role="menu" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={() => {}}>
            {#each EXPORTS as [f, label]}
              <button onclick={() => doExport(f)}>{label}</button>
            {/each}
          </div>
        {/if}
      </div>
      <button class="ghost" onclick={() => compareScans(app.graphTarget || app.target.trim())} disabled={app.running || !(app.graphTarget || app.target.trim())} title="Oxirgi ikki scan'ni grafda solishtirish">🔁 Diff</button>
      <button class="ghost" class:on={app.drawer === "history"} onclick={() => app.toggleDrawer("history")} title="Scan tarixi">🕓 Tarix</button>
      <button class="ghost" class:on={app.drawer === "monitor"} onclick={() => app.toggleDrawer("monitor")} title="Monitoring">🔔</button>
      <button class="ghost" class:on={app.drawer === "sources"} onclick={() => app.toggleDrawer("sources")} title="Manbalar / vaqtlar">⚙️</button>
      <button class="ghost" onclick={() => (showSettings = true)} title="Sozlamalar">⚙</button>
    </div>
  </header>

  {#if app.toast}<div class="toast">{app.toast}</div>{/if}
  {#if app.error}<div class="error">{app.error}</div>{/if}

  <div class="body">
    <div class="graph" bind:this={graphEl} class:hidden={app.mode !== "graph"}></div>

    {#if app.mode === "graph"}
      <div class="graph-search">
        <input
          type="search"
          placeholder="🔍 Grafda qidirish…"
          bind:value={graphSearch}
          oninput={runGraphSearch}
        />
      </div>
    {/if}
    {#if app.mode === "table"}<TableView />{/if}
    {#if app.mode === "gallery"}<Gallery />{/if}

    {#if app.diff}
      <div class="diff-banner" class:with-drawer={!!app.drawer}>
        <span>🔁 <strong>{app.diff.target}</strong> — oldingi scan bilan farq:</span>
        <span class="plus">+{app.diff.added} yangi</span>
        <span class="minus">−{app.diff.removed} yo'qolgan</span>
        <button class="ghost sm" onclick={exitDiff}>✕ Diffdan chiqish</button>
      </div>
    {/if}

    {#if app.mode === "graph"}
    <div class="zoom-controls">
      <button title="Kattalashtirish" onclick={() => app.view?.zoomBy(1.25)}>＋</button>
      <button title="Kichiklashtirish" onclick={() => app.view?.zoomBy(0.8)}>－</button>
      <button title="Hammasini sig'dirish" onclick={() => app.view?.fit()}>⤢</button>
      <button title="Qayta joylash" onclick={() => app.view?.relayout()}>↻</button>
    </div>
    {/if}

    <Legend />
    <DetailPanel />
    {#if app.drawer === "history"}<HistoryDrawer />{/if}
    {#if app.drawer === "monitor"}<MonitorDrawer />{/if}
    {#if app.drawer === "sources"}<SourcesDrawer />{/if}
  </div>

  <Footer />
  <SettingsModal bind:open={showSettings} />
</div>
