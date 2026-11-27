<script lang="ts">
  import { app, errMsg } from "../lib/state.svelte";
  import { MonitorList, MonitorAdd, MonitorRemove, NotifyTest, type Watch, type AlertFilter } from "../lib/api";
  import { when } from "../lib/actions";

  // Alert filter presets — mirror PresetFilter in monitor_filter.go.
  const PRESETS: Record<string, { label: string; filter: AlertFilter }> = {
    important: {
      label: "Важные изменения (рекомендуется)",
      filter: { preset: "important", types: ["domain", "subdomain", "ip", "port", "service", "certificate", "cve", "finding", "bucket"] },
    },
    critical: { label: "Только опасное (high/critical, новые порты)", filter: { preset: "critical", types: ["port", "cve", "finding", "bucket"], minSeverity: "high", ignoreRemoved: true } },
    all: { label: "Все изменения", filter: { preset: "all" } },
    custom: { label: "Выбрать вручную…", filter: { preset: "custom" } },
  };
  // Node types the user can pick, grouped under readable names.
  const TYPES: { label: string; types: string[] }[] = [
    { label: "Поддомены", types: ["domain", "subdomain"] },
    { label: "IP-адреса", types: ["ip"] },
    { label: "Открытые порты", types: ["port"] },
    { label: "Сервисы", types: ["service"] },
    { label: "Находки", types: ["finding"] },
    { label: "CVE", types: ["cve"] },
    { label: "Сертификаты", types: ["certificate"] },
    { label: "URL / эндпоинты", types: ["url"] },
    { label: "Параметры", types: ["param"] },
    { label: "Технологии", types: ["technology"] },
    { label: "Email-адреса", types: ["email"] },
    { label: "ASN / WHOIS", types: ["asn", "whois_org"] },
  ];
  const SEVERITIES = [
    ["", "любая"],
    ["low", "low и выше"],
    ["medium", "medium и выше"],
    ["high", "high и выше"],
    ["critical", "только critical"],
  ];

  let watches = $state<Watch[]>([]);
  let target = $state("");
  let interval = $state(360);
  let consent = $state(false);
  let preset = $state("important");
  // custom filter state
  let picked = $state<string[]>(["Поддомены", "IP-адреса", "Открытые порты", "Находки", "CVE"]);
  let minSeverity = $state("");
  let ignoreRemoved = $state(false);

  function currentFilter(): AlertFilter {
    if (preset !== "custom") return PRESETS[preset].filter;
    const types = TYPES.filter((g) => picked.includes(g.label)).flatMap((g) => g.types);
    return { preset: "custom", types, minSeverity, ignoreRemoved };
  }

  /** One-line description of a watch's filter. */
  function describe(f?: AlertFilter): string {
    if (!f || (!f.types?.length && !f.minSeverity && !f.ignoreRemoved)) return "все изменения";
    if (f.preset && f.preset !== "custom" && PRESETS[f.preset]) return PRESETS[f.preset].label.replace(" (рекомендуется)", "").toLowerCase();
    const names = TYPES.filter((g) => g.types.some((t) => f.types?.includes(t))).map((g) => g.label.toLowerCase());
    let s = names.length ? names.join(", ") : "все типы";
    if (f.minSeverity) s += ` · ${f.minSeverity}+`;
    if (f.ignoreRemoved) s += " · только новые";
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
      app.flash("Введите цель");
      return;
    }
    const f = currentFilter();
    if (preset === "custom" && !f.types?.length) {
      app.flash("Отметьте хотя бы один тип");
      return;
    }
    try {
      await MonitorAdd(t, interval, consent, f);
      target = "";
      load();
      app.flash("✅ Наблюдение сохранено: " + t);
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
      app.flash("✅ Тестовое сообщение отправлено");
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
    <h2>🔔 Мониторинг</h2>
    <button class="ghost sm" onclick={() => (app.drawer = null)} aria-label="Закрыть">✕</button>
  </div>
  <p class="muted sm">Цель автоматически пересканируется с заданным интервалом; если появятся изменения, подходящие под фильтр, придёт уведомление в Telegram или на вебхук.</p>

  <div class="mon-add">
    <input type="text" placeholder="Цель (пусто = текущая)" bind:value={target} />
    <label class="mon-int">Каждые
      <select bind:value={interval}>
        <option value={5}>5 минут</option>
        <option value={60}>1 час</option>
        <option value={360}>6 часов</option>
        <option value={720}>12 часов</option>
        <option value={1440}>1 день</option>
      </select>
    </label>
    <label class="mon-int">Уведомлять
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
        <label class="mon-int">Серьёзность находок/CVE
          <select bind:value={minSeverity}>
            {#each SEVERITIES as [v, l]}<option value={v}>{l}</option>{/each}
          </select>
        </label>
        <label class="row sm"><input type="checkbox" bind:checked={ignoreRemoved} /> Только новые (не сообщать об исчезнувших)</label>
      </div>
    {/if}
    <label class="row sm"><input type="checkbox" bind:checked={consent} /> Активное сканирование (есть разрешение)</label>
    <div class="mon-actions">
      <button class="primary sm" onclick={add}>💾 Сохранить</button>
      <button class="ghost sm" onclick={testNotify}>✈ Тестовое сообщение</button>
    </div>
  </div>

  {#if watches.length === 0}
    <p class="muted center sm">Пока нет целей под наблюдением.</p>
  {/if}
  <ul class="mon-list">
    {#each watches as w (w.target)}
      <li>
        <div class="mon-line">
          <span class="name">{w.target}</span>
          <span>
            <button class="ghost sm" onclick={() => edit(w)} title="Изменить">✏️</button>
            <button class="ghost sm danger-text" onclick={() => remove(w.target)} title="Удалить">🗑</button>
          </span>
        </div>
        <div class="meta">Каждые {w.intervalMin} мин · следующее {when(w.nextRun)}{w.consent ? " · активное" : ""}</div>
        <div class="meta mon-filter-sum">🔎 {describe(w.filter)}</div>
        {#if w.lastChange}<div class="mon-change">🔁 {w.lastChange}</div>{/if}
      </li>
    {/each}
  </ul>
</aside>
