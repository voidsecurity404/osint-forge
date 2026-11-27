<script lang="ts">
  import { app, errMsg } from "../lib/state.svelte";
  import { MonitorList, MonitorAdd, MonitorRemove, NotifyTest, type Watch, type AlertFilter } from "../lib/api";
  import { when } from "../lib/actions";

  // Alert filter presets — mirror PresetFilter in monitor_filter.go.
  const PRESETS: Record<string, { label: string; filter: AlertFilter }> = {
    important: {
      label: "Muhim o'zgarishlar (tavsiya)",
      filter: { preset: "important", types: ["domain", "subdomain", "ip", "port", "service", "certificate", "cve", "finding", "bucket"] },
    },
    critical: { label: "Faqat xavfli (high/critical, yangi port)", filter: { preset: "critical", types: ["port", "cve", "finding", "bucket"], minSeverity: "high", ignoreRemoved: true } },
    all: { label: "Hamma o'zgarishlar", filter: { preset: "all" } },
    custom: { label: "O'zim tanlayman…", filter: { preset: "custom" } },
  };
  // Node types the user can pick, grouped under readable names.
  const TYPES: { label: string; types: string[] }[] = [
    { label: "Subdomenlar", types: ["domain", "subdomain"] },
    { label: "IP manzillar", types: ["ip"] },
    { label: "Ochiq portlar", types: ["port"] },
    { label: "Servislar", types: ["service"] },
    { label: "Topilmalar", types: ["finding"] },
    { label: "CVE", types: ["cve"] },
    { label: "Sertifikatlar", types: ["certificate"] },
    { label: "URL / endpointlar", types: ["url"] },
    { label: "Parametrlar", types: ["param"] },
    { label: "Texnologiyalar", types: ["technology"] },
    { label: "Email'lar", types: ["email"] },
    { label: "ASN / WHOIS", types: ["asn", "whois_org"] },
  ];
  const SEVERITIES = [
    ["", "har qanday"],
    ["low", "low va yuqori"],
    ["medium", "medium va yuqori"],
    ["high", "high va yuqori"],
    ["critical", "faqat critical"],
  ];

  let watches = $state<Watch[]>([]);
  let target = $state("");
  let interval = $state(360);
  let consent = $state(false);
  let preset = $state("important");
  // custom filter state
  let picked = $state<string[]>(["Subdomenlar", "IP manzillar", "Ochiq portlar", "Topilmalar", "CVE"]);
  let minSeverity = $state("");
  let ignoreRemoved = $state(false);

  function currentFilter(): AlertFilter {
    if (preset !== "custom") return PRESETS[preset].filter;
    const types = TYPES.filter((g) => picked.includes(g.label)).flatMap((g) => g.types);
    return { preset: "custom", types, minSeverity, ignoreRemoved };
  }

  /** One-line description of a watch's filter. */
  function describe(f?: AlertFilter): string {
    if (!f || (!f.types?.length && !f.minSeverity && !f.ignoreRemoved)) return "hamma o'zgarishlar";
    if (f.preset && f.preset !== "custom" && PRESETS[f.preset]) return PRESETS[f.preset].label.replace(" (tavsiya)", "").toLowerCase();
    const names = TYPES.filter((g) => g.types.some((t) => f.types?.includes(t))).map((g) => g.label.toLowerCase());
    let s = names.length ? names.join(", ") : "hamma turlar";
    if (f.minSeverity) s += ` · ${f.minSeverity}+`;
    if (f.ignoreRemoved) s += " · faqat yangilar";
    return s;
  }

  async function load() {
    try {
      watches = await MonitorList();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
  async function add() {
    const t = (target || app.graphTarget || app.target).trim();
    if (!t) {
      app.flash("Nishon kiriting");
      return;
    }
    const f = currentFilter();
    if (preset === "custom" && !f.types?.length) {
      app.flash("Kamida bitta turni belgilang");
      return;
    }
    try {
      await MonitorAdd(t, interval, consent, f);
      target = "";
      load();
      app.flash("✅ Kuzatuv saqlandi: " + t);
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
  /** Load a watch into the form so its interval/filter can be changed. */
  function edit(w: Watch) {
    target = w.target;
    interval = w.intervalMin;
    consent = w.consent;
    const f = w.filter ?? {};
    if (f.preset && f.preset !== "custom" && PRESETS[f.preset]) preset = f.preset;
    else if (!f.types?.length && !f.minSeverity && !f.ignoreRemoved) preset = "all";
    else {
      preset = "custom";
      picked = TYPES.filter((g) => g.types.some((t) => f.types?.includes(t))).map((g) => g.label);
      minSeverity = f.minSeverity ?? "";
      ignoreRemoved = !!f.ignoreRemoved;
    }
  }
  async function remove(t: string) {
    try {
      await MonitorRemove(t);
      load();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
  async function testNotify() {
    try {
      await NotifyTest();
      app.flash("✅ Test xabari yuborildi");
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }

  $effect(() => {
    app.running; // refresh after scans
    load();
  });
</script>

<aside class="drawer">
  <div class="drawer-head">
    <h2>🔔 Monitoring</h2>
    <button class="ghost sm" onclick={() => (app.drawer = null)} aria-label="Yopish">✕</button>
  </div>
  <p class="muted sm">Nishonni belgilangan oraliqda avtomatik qayta skanlaydi; filtrga mos o'zgarish chiqsa, Telegram yoki webhook orqali xabar yuboradi.</p>

  <div class="mon-add">
    <input type="text" placeholder="Nishon (bo'sh = joriy)" bind:value={target} />
    <label class="mon-int">Har
      <select bind:value={interval}>
        <option value={5}>5 daqiqa</option>
        <option value={60}>1 soat</option>
        <option value={360}>6 soat</option>
        <option value={720}>12 soat</option>
        <option value={1440}>1 kun</option>
      </select>
    </label>
    <label class="mon-int">Xabar
      <select bind:value={preset} class="mon-preset">
        {#each Object.entries(PRESETS) as [k, p]}<option value={k}>{p.label}</option>{/each}
      </select>
    </label>
    {#if preset === "custom"}
      <div class="mon-filter">
        <div class="mon-types">
          {#each TYPES as g}
            <label class="row sm"><input type="checkbox" bind:group={picked} value={g.label} /> {g.label}</label>
          {/each}
        </div>
        <label class="mon-int">Topilma/CVE jiddiyligi
          <select bind:value={minSeverity}>
            {#each SEVERITIES as [v, l]}<option value={v}>{l}</option>{/each}
          </select>
        </label>
        <label class="row sm"><input type="checkbox" bind:checked={ignoreRemoved} /> Faqat yangilar (yo'qolganlar haqida xabar bermaslik)</label>
      </div>
    {/if}
    <label class="row sm"><input type="checkbox" bind:checked={consent} /> Aktiv skan (ruxsatim bor)</label>
    <div class="mon-actions">
      <button class="primary sm" onclick={add}>💾 Saqlash</button>
      <button class="ghost sm" onclick={testNotify}>✈ Test xabar</button>
    </div>
  </div>

  {#if watches.length === 0}
    <p class="muted center sm">Hali kuzatuvdagi nishon yo'q.</p>
  {/if}
  <ul class="mon-list">
    {#each watches as w (w.target)}
      <li>
        <div class="mon-line">
          <span class="name">{w.target}</span>
          <span>
            <button class="ghost sm" onclick={() => edit(w)} title="Tahrirlash">✏️</button>
            <button class="ghost sm danger-text" onclick={() => remove(w.target)} title="O'chirish">🗑</button>
          </span>
        </div>
        <div class="meta">Har {w.intervalMin} daq · keyingi {when(w.nextRun)}{w.consent ? " · aktiv" : ""}</div>
        <div class="meta mon-filter-sum">🔎 {describe(w.filter)}</div>
        {#if w.lastChange}<div class="mon-change">🔁 {w.lastChange}</div>{/if}
      </li>
    {/each}
  </ul>
</aside>
