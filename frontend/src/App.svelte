<script lang="ts">
  import { onMount } from "svelte";
  import { GraphView, type Neighbor } from "./lib/graph";
  import {
    StartScan,
    CancelScan,
    GetConfig,
    SaveConfig,
    NmapInstalled,
    OpenURL,
    ExportObsidian,
    ExportJSON,
    ExportHTML,
    ExportMarkdown,
    ExportCSV,
    ExportSARIF,
    DiffPrevious,
    FetchPage,
  } from "../wailsjs/go/main/App";
  import { EventsOn } from "../wailsjs/runtime/runtime";
  import { config, core, graph } from "../wailsjs/go/models";

  let graphEl: HTMLDivElement;
  let targetEl: HTMLInputElement;
  let view: GraphView;

  let target = $state("");
  let consent = $state(false);
  let running = $state(false);
  let nmapOk = $state(false);
  let error = $state("");

  let selected = $state<graph.Node | null>(null);
  let logs = $state<core.LogLine[]>([]);
  let progress = $state<core.Progress | null>(null);
  let showLogs = $state(true);
  let showSettings = $state(false);
  let showExport = $state(false);
  let cfg = $state<config.Config | null>(null);
  let toast = $state("");
  let pageView = $state<any>(null);
  let pageLoading = $state(false);

  // Delta coalescing buffer (plain, non-reactive) — shared so start()/finish can
  // flush or discard it.
  let pending: { nodes: any[]; edges: any[] } | null = null;
  let rafScheduled = false;
  function flushPending() {
    const p = pending;
    pending = null;
    rafScheduled = false;
    if (p && view) view.apply(p as unknown as graph.Delta);
  }

  // Live element counts, updated from the graph itself on every delta (the
  // progress event only fires per-stage, so it lagged badly during a scan).
  let liveCounts = $state({ nodes: 0, edges: 0 });

  // Human-readable explanation of each node type (shown in the panel).
  const TYPE_DESC: Record<string, string> = {
    ip: "IP manzil — nishonning internetdagi manzili. Unga ulangan domenlar, portlar va ASN quyida ko'rinadi.",
    domain: "Domen nomi — asosiy nishon. Subdomenlar, DNS yozuvlari va WHOIS ma'lumotlari shunga bog'langan.",
    subdomain: "Subdomen / host nomi — DNS, crt.sh, reverse-IP yoki sertifikatdan topilgan.",
    port: "Ochiq TCP port — nmap yoki fallback skaner tomonidan aniqlangan.",
    service: "Portda ishlayotgan servis va versiyasi (nmap -sV). Bu versiya CVE qidirish uchun ishlatiladi.",
    technology: "Aniqlangan veb-texnologiya (server, framework yoki CMS).",
    certificate: "TLS/SSL sertifikati — egasi, chiqaruvchi va amal qilish muddati. SAN domenlari ichki hostlarni oshkor qilishi mumkin.",
    asn: "Avtonom tizim (ASN) — IP'ni internetga yo'naltiruvchi tarmoq operatori. Bir ASN ostidagi IP'lar bir tashkilotniki.",
    whois_org: "WHOIS/RDAP bo'yicha ro'yxatga oluvchi yoki egasi tashkilot.",
    url: "Topilgan URL / endpoint. Status kodi, HTML va texnologiyalar bu bilan bog'langan.",
    email: "Veb-sahifada topilgan email manzil — ijtimoiy injiniring yoki aloqa uchun.",
    cve: "Ma'lum zaiflik (CVE). Quyida og'irligi, CVSS bali va tavsifi; qaysi servisga tegishli ekani 'Bog'lanishlar' da.",
    finding: "Xavfsizlik topilmasi / noto'g'ri sozlama. Og'irligi va tavsifi quyida; qaysi nishonga tegishli ekani 'Bog'lanishlar' da.",
  };

  const connections = $derived.by<Neighbor[]>(() =>
    selected && view ? view.neighborsOf(selected.id) : [],
  );

  function urlForNode(n: graph.Node): string | null {
    if (n.props?.url) return String(n.props.url); // e.g. CVE → NVD link
    if (n.type === "url") return n.id.replace(/^url:/, "");
    return null;
  }
  function openNode(n: graph.Node) {
    const u = urlForNode(n);
    if (u) OpenURL(u);
  }

  onMount(() => {
    view = new GraphView(graphEl, (n) => (selected = n));
    NmapInstalled().then((v) => (nmapOk = v));
    targetEl?.focus(); // cursor ready in the target field on open

    // Coalesce bursts of deltas into one apply per animation frame so a flood of
    // backend events never thrashes the renderer. A setTimeout runs alongside the
    // rAF as a fallback, so deltas still apply when the tab is hidden (rAF paused);
    // whichever fires first flushes, the other becomes a no-op.
    const doFlush = () => {
      if (!pending) return;
      flushPending();
      liveCounts = view.counts();
      if (running) view.fitDuringScan();
    };
    const offDelta = EventsOn("scan:delta", (d: graph.Delta) => {
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
      logs = [...logs.slice(-300), l];
    });
    const offProg = EventsOn("scan:progress", (p: core.Progress) => {
      progress = p;
      if (p.finished) {
        running = false;
        flushPending(); // apply any buffered deltas before the final layout
        liveCounts = view.counts();
        view.finalize(); // one clean settle + fit when the scan ends
      }
    });
    return () => {
      offDelta();
      offLog();
      offProg();
      view.destroy();
    };
  });

  async function start() {
    error = "";
    if (!target.trim()) {
      error = "Enter an IP address or domain.";
      return;
    }
    logs = [];
    selected = null;
    progress = null;
    pending = null; // discard any stragglers from a previous scan
    rafScheduled = false;
    liveCounts = { nodes: 0, edges: 0 };
    view.reset();
    running = true;
    try {
      await StartScan(target.trim(), consent);
    } catch (e: any) {
      error = String(e);
      running = false;
    }
  }

  async function cancel() {
    await CancelScan();
    running = false;
  }

  function flash(msg: string) {
    toast = msg;
    setTimeout(() => (toast = ""), 4000);
  }

  async function viewHTML(n: graph.Node) {
    const u = urlForNode(n);
    if (!u) return;
    pageLoading = true;
    pageView = { url: u, status: 0, body: "", title: "", server: "" };
    try {
      pageView = await FetchPage(u);
    } catch (e: any) {
      pageView = { url: u, status: 0, body: "Xatolik: " + String(e), title: "", server: "" };
    } finally {
      pageLoading = false;
    }
  }

  async function exportObsidian() {
    try {
      const res = await ExportObsidian();
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function exportJSON() {
    try {
      const res = await ExportJSON();
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function exportHTML() {
    try {
      const res = await ExportHTML(target.trim());
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function exportMarkdown() {
    try {
      const res = await ExportMarkdown(target.trim());
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function exportCSV() {
    try {
      const res = await ExportCSV();
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function exportSARIF() {
    try {
      const res = await ExportSARIF(target.trim());
      if (res) flash("✅ " + res);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }
  async function showDiff() {
    try {
      const d = await DiffPrevious(target.trim());
      if (!d || !d.hasPrevious) {
        flash("ℹ️ Oldingi scan topilmadi — taqqoslash uchun yana bir marta skanlang");
        return;
      }
      const added = d.added ? d.added.length : 0;
      const removed = d.removed ? d.removed.length : 0;
      flash(`🔁 O'zgarishlar: +${added} yangi, −${removed} yo'qolgan`);
    } catch (e: any) {
      flash("❌ " + String(e));
    }
  }

  async function openSettings() {
    cfg = await GetConfig();
    showSettings = true;
  }
  async function saveSettings() {
    if (cfg) await SaveConfig(cfg);
    showSettings = false;
  }

  function propEntries(n: graph.Node): [string, any][] {
    if (!n.props) return [];
    return Object.entries(n.props).filter(([k]) => k !== "root");
  }

  function fmt(v: any): string {
    if (Array.isArray(v)) return v.join(", ");
    if (typeof v === "object" && v !== null) return JSON.stringify(v);
    return String(v);
  }
</script>

<svelte:window onclick={() => (showExport = false)} />

<div class="app">
  <header>
    <div class="brand">🕸️ <span>osint-forge</span></div>
    <div class="controls">
      <input
        type="text"
        bind:this={targetEl}
        bind:value={target}
        placeholder="IP yoki domen kiriting — masalan 1.1.1.1 yoki example.com"
        onkeydown={(e) => e.key === "Enter" && !running && start()}
        disabled={running}
      />
      <label class="consent" title="Faqat o'zingizga tegishli yoki ruxsat berilgan nishonlarni skanerlang">
        <input type="checkbox" bind:checked={consent} disabled={running} />
        Aktiv skan (nmap/HTTP) — ruxsatim bor
      </label>
      {#if running}
        <button class="danger" onclick={cancel}>To'xtatish</button>
      {:else}
        <button class="primary" onclick={start}>Skanlash</button>
      {/if}
      <div class="dropdown">
        <button
          class="ghost"
          disabled={running}
          title="Hisobotni eksport qilish"
          onclick={(e) => {
            e.stopPropagation();
            showExport = !showExport;
          }}
        >⬇ Eksport ▾</button>
        {#if showExport}
          <div class="menu" onclick={(e) => e.stopPropagation()}>
            <button onclick={() => { showExport = false; exportObsidian(); }}>Obsidian vault</button>
            <button onclick={() => { showExport = false; exportHTML(); }}>HTML</button>
            <button onclick={() => { showExport = false; exportMarkdown(); }}>Markdown</button>
            <button onclick={() => { showExport = false; exportCSV(); }}>CSV</button>
            <button onclick={() => { showExport = false; exportSARIF(); }}>SARIF</button>
            <button onclick={() => { showExport = false; exportJSON(); }}>JSON</button>
          </div>
        {/if}
      </div>
      <button class="ghost" onclick={showDiff} disabled={running} title="Oldingi scan bilan solishtirish">🔁 Diff</button>
      <button class="ghost" onclick={openSettings} title="Sozlamalar">⚙</button>
    </div>
  </header>

  {#if toast}<div class="toast">{toast}</div>{/if}

  {#if error}<div class="error">{error}</div>{/if}

  <div class="body">
    <div class="graph" bind:this={graphEl}></div>

    <div class="zoom-controls">
      <button title="Kattalashtirish" onclick={() => view.zoomBy(1.25)}>＋</button>
      <button title="Kichiklashtirish" onclick={() => view.zoomBy(0.8)}>－</button>
      <button title="Hammasini sig'dirish" onclick={() => view.fit()}>⤢</button>
      <button title="Qayta joylash" onclick={() => view.relayout()}>↻</button>
    </div>

    {#if selected}
      <aside class="detail">
        <div class="detail-head">
          <span class="type-chip" data-type={selected.type}>{selected.type}</span>
          <button class="ghost sm" onclick={() => (selected = null)}>✕</button>
        </div>
        <h2>{selected.label}</h2>
        <div class="id">{selected.id}</div>

        <p class="desc">{TYPE_DESC[selected.type] ?? "Topilgan element."}</p>

        {#if selected.type === "cve" && selected.props?.summary}
          <div class="cve-box">
            <div class="cve-meta">
              <span class="sev {String(selected.props.severity).toLowerCase()}">{selected.props.severity}</span>
              {#if selected.props.score}<span class="score">CVSS {selected.props.score}</span>{/if}
            </div>
            {#if selected.props.known_exploited}
              <div class="kev-warn">⚠️ Faol ekspluatatsiya qilinmoqda (CISA KEV)</div>
            {/if}
            {#if selected.props.epss != null}
              <div class="score">EPSS: {(Number(selected.props.epss) * 100).toFixed(1)}% (30 kun ichida ekspluatatsiya ehtimoli)</div>
            {/if}
            <p class="cve-sum">{selected.props.summary}</p>
          </div>
        {/if}

        {#if selected.type === "finding"}
          <div class="cve-box">
            <div class="cve-meta">
              <span class="sev {String(selected.props?.severity).toLowerCase()}">{selected.props?.severity}</span>
            </div>
            {#if selected.props?.description}<p class="cve-sum">{selected.props.description}</p>{/if}
          </div>
        {/if}

        {#if selected.props?.status}
          <div class="statusline">
            HTTP <span class="code s{Math.floor(Number(selected.props.status) / 100)}">{selected.props.status}</span>
          </div>
        {/if}

        {#if urlForNode(selected)}
          <div class="node-actions">
            <button class="primary sm" onclick={() => openNode(selected!)}>🌐 Brauzerda ochish</button>
            {#if selected.type === "url"}
              <button class="ghost sm" onclick={() => viewHTML(selected!)}>📄 HTML ko'rish</button>
            {/if}
          </div>
        {/if}

        <table>
          <tbody>
            {#each propEntries(selected) as [k, v]}
              <tr>
                <th>{k}</th>
                <td>
                  {#if typeof v === "string" && v.startsWith("http")}
                    <a class="link" onclick={() => OpenURL(v)}>{v}</a>
                  {:else}
                    {fmt(v)}
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if propEntries(selected).length === 0}
          <p class="muted">Qo'shimcha ma'lumot yo'q.</p>
        {/if}

        {#if connections.length > 0}
          <h3 class="section">Bog'lanishlar ({connections.length})</h3>
          <ul class="conns">
            {#each connections as c}
              <li>
                <span class="rel">{c.dir === "out" ? "→" : "←"} {c.rel}</span>
                <span class="conn-chip" data-type={c.type}>{c.type}</span>
                <span class="conn-label">{c.label}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </aside>
    {/if}
  </div>

  <footer>
    <div class="status">
      <span class="dot" class:on={running}></span>
      {#if progress}
        <strong>{progress.phase}</strong>
        {#if progress.running}· {progress.running}{/if}
        · {progress.done}/{progress.total}
      {:else}
        Tayyor
      {/if}
      <span class="sep">|</span>
      <span>{liveCounts.nodes} tugun · {liveCounts.edges} bog'lanish</span>
      {#if !nmapOk}
        <span class="sep">|</span><span class="warn">nmap o'rnatilmagan — fallback skaner</span>
      {/if}
      <span class="grow"></span>
      <button class="ghost sm" onclick={() => (showLogs = !showLogs)}>
        {showLogs ? "Loglarni yashirish" : "Loglar"}
      </button>
    </div>
    {#if showLogs}
      <div class="logs">
        {#each logs as l}
          <div class="log {l.level}"><span class="src">{l.source}</span> {l.message}</div>
        {/each}
        {#if logs.length === 0}<div class="muted">Loglar shu yerda ko'rinadi…</div>{/if}
      </div>
    {/if}
  </footer>

  {#if showSettings && cfg}
    <div class="modal-bg" onclick={() => (showSettings = false)}>
      <div class="modal" onclick={(e) => e.stopPropagation()}>
        <h2>Sozlamalar</h2>
        <label>SecurityTrails API kalit
          <input type="password" bind:value={cfg.securitytrails_key} /></label>
        <label>VirusTotal API kalit
          <input type="password" bind:value={cfg.virustotal_key} /></label>
        <label>NVD API kalit (ixtiyoriy)
          <input type="password" bind:value={cfg.nvd_key} /></label>
        <label>nmap argumentlari
          <input type="text" bind:value={cfg.nmap_args} /></label>
        <label>Ko'rsatiladigan status kodlar
          <input type="text" bind:value={cfg.status_codes} placeholder="2xx,3xx,401,403,5xx" />
          <span class="hint">Masalan: 200,301,403 yoki 2xx,3xx,5xx · bo'sh = hammasi</span></label>
        <label>Parallellik
          <input type="number" bind:value={cfg.max_concurrent} /></label>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.fuzz_enabled} />
          Path fuzzing (jonli web host'larni yo'llar bo'yicha tekshirish)
        </label>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.subdomain_bruteforce} />
          Subdomain bruteforce (DNS, 5000 nom)
        </label>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.zone_transfer} />
          Zone transfer (AXFR) sinovi
        </label>
        <label>Fuzz wordlist (SecLists)
          <select bind:value={cfg.fuzz_wordlist}>
            <option value="common">common (~4.7k, tez)</option>
            <option value="raft-directories">raft-directories (~30k)</option>
            <option value="raft-files">raft-files (~17k)</option>
            <option value="combo">combo (dirs+files)</option>
          </select>
        </label>

        <h3 class="settings-group">Xavfsizlik / qamrov</h3>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.scope_strict} />
          Scope guard — faqat nishon domen/IP'ga active skan (tavsiya etiladi)
        </label>
        <label>Scan vaqt chegarasi (daqiqa, 0 = cheksiz)
          <input type="number" bind:value={cfg.scan_timeout_min} /></label>
        <label>So'rov tezligi cheklovi (host uchun /sek, 0 = default)
          <input type="number" bind:value={cfg.rate_limit_per_host} /></label>

        <h3 class="settings-group">Qo'shimcha manbalar (API kalit)</h3>
        <label>Shodan API kalit
          <input type="password" bind:value={cfg.shodan_key} /></label>
        <label>Censys API ID
          <input type="password" bind:value={cfg.censys_id} /></label>
        <label>Censys secret
          <input type="password" bind:value={cfg.censys_secret} /></label>
        <label>HaveIBeenPwned API kalit
          <input type="password" bind:value={cfg.hibp_key} /></label>
        <label>GitHub token (kod qidiruvi)
          <input type="password" bind:value={cfg.github_token} /></label>

        <h3 class="settings-group">Tashqi dasturlar</h3>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.nuclei} />
          Nuclei shablonli skan (nuclei o'rnatilgan bo'lsa)
        </label>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.screenshots} />
          Jonli web host'lar skrinshoti (chromium o'rnatilgan bo'lsa)
        </label>
        <label class="row">
          <input type="checkbox" bind:checked={cfg.favicon_hash} />
          Favicon hash (Shodan uslubida mmh3)
        </label>

        <div class="modal-actions">
          <button class="ghost" onclick={() => (showSettings = false)}>Bekor</button>
          <button class="primary" onclick={saveSettings}>Saqlash</button>
        </div>
      </div>
    </div>
  {/if}

  {#if pageView}
    <div class="modal-bg" onclick={() => (pageView = null)}>
      <div class="modal wide" onclick={(e) => e.stopPropagation()}>
        <div class="detail-head">
          <h2>Sahifa manbasi</h2>
          <button class="ghost sm" onclick={() => (pageView = null)}>✕</button>
        </div>
        <div class="statusline">
          {#if pageLoading}Yuklanmoqda…{:else}
            HTTP <span class="code s{Math.floor(Number(pageView.status) / 100)}">{pageView.status}</span>
            {#if pageView.server}· {pageView.server}{/if}
          {/if}
        </div>
        <a class="link" onclick={() => OpenURL(pageView.url)}>{pageView.url}</a>
        <pre class="html">{pageView.body}</pre>
      </div>
    </div>
  {/if}
</div>
