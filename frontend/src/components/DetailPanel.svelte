<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { statusOf, statusClassOf, type Neighbor } from "../lib/graph";
  import { OpenURL, FetchPage } from "../lib/api";
  import type { graph } from "../lib/models";
  import NotesEditor from "./NotesEditor.svelte";
  import NextStep from "./NextStep.svelte";
  import ShotPreview from "./ShotPreview.svelte";
  import { typeName, severityName } from "../lib/i18n";

  // Human-readable explanation of each node type (shown in the panel).
  const TYPE_DESC: Record<string, string> = {
    ip: "IP-адрес — адрес цели в интернете. Связанные с ним домены, порты и ASN показаны ниже.",
    domain: "Доменное имя — основная цель. К нему привязаны поддомены, DNS-записи и данные WHOIS.",
    subdomain: "Поддомен / имя хоста — найден через DNS, crt.sh, reverse-IP или сертификат.",
    port: "Открытый TCP-порт — обнаружен nmap или резервным сканером.",
    service: "Сервис на порту и его версия (nmap -sV). По версии ищутся CVE.",
    technology: "Обнаруженная веб-технология (сервер, фреймворк или CMS).",
    certificate: "TLS/SSL-сертификат — владелец, издатель и срок действия. Домены в SAN могут раскрыть внутренние хосты.",
    asn: "Автономная система (ASN) — сетевой оператор, маршрутизирующий IP в интернет. IP одной ASN обычно принадлежат одной организации.",
    whois_org: "Регистратор или организация-владелец по данным WHOIS/RDAP.",
    url: "Найденный URL / эндпоинт. С ним связаны код статуса, HTML и технологии.",
    email: "Email-адрес, найденный на веб-странице, — для социальной инженерии или связи.",
    cve: "Известная уязвимость (CVE). Ниже — серьёзность, оценка CVSS и описание; к какому сервису она относится — в разделе «Связи».",
    finding: "Находка безопасности / ошибка конфигурации. Серьёзность и описание ниже; к какой цели она относится — в разделе «Связи».",
    param: "Параметр URL — собран из архива и JS. Тип (SQLi, XSS, redirect…) означает, что параметр — кандидат для ручной проверки.",
    bucket: "Облачное хранилище (S3 / GCS / Azure).",
  };

  // Pretty candidate badges for param nodes.
  function candidateKinds(n: graph.Node): string[] {
    const c = n.props?.candidate;
    return typeof c === "string" && c ? c.split(",").map((x) => x.trim()) : [];
  }

  const node = $derived(app.selected);
  const connections = $derived.by<Neighbor[]>(() => {
    app.version; // recompute as the graph grows
    return node && app.view ? app.view.neighborsOf(node.id) : [];
  });

  let pageView = $state<any>(null);
  let pageLoading = $state(false);

  function urlForNode(n: graph.Node): string | null {
    if (n.props?.url) return String(n.props.url); // e.g. CVE → NVD link
    if (n.type === "url") return n.id.replace(/^url:/, "");
    return null;
  }

  async function viewHTML(n: graph.Node) {
    const u = urlForNode(n);
    if (!u) return;
    pageLoading = true;
    pageView = { url: u, status: 0, body: "", title: "", server: "" };
    try {
      pageView = await FetchPage(u);
    } catch (e: any) {
      pageView = { url: u, status: 0, body: "Ошибка: " + String(e?.message ?? e), title: "", server: "" };
    } finally {
      pageLoading = false;
    }
  }

  // Internal/UI-only props are not shown in the generic table (the screenshot
  // has its own preview under the action buttons).
  const HIDDEN = new Set(["root", "screenshot"]);
  function propEntries(n: graph.Node): [string, any][] {
    if (!n.props) return [];
    return Object.entries(n.props).filter(([k]) => !HIDDEN.has(k));
  }
  function fmt(v: any): string {
    if (Array.isArray(v)) return v.join(", ");
    if (typeof v === "object" && v !== null) return JSON.stringify(v);
    return String(v);
  }
  function close() {
    app.selected = null;
  }
</script>

{#if node}
  <aside class="detail">
    <div class="detail-head">
      <span class="type-chip" data-type={node.type}>{typeName(node.type)}</span>
      <button class="ghost sm" onclick={close} aria-label="Закрыть">✕</button>
    </div>
    <h2>{node.label}</h2>
    <div class="id">{node.id}</div>
    {#if statusOf(node) != null}
      {@const sc = statusClassOf(statusOf(node))}
      <div class="http-status" style="--sc:{sc?.color}">
        <span class="code">HTTP {statusOf(node)}</span>
        <span class="hint">{sc?.hint}</span>
      </div>
    {/if}

    {#if node.props?.cdn || node.props?.waf}
      <div class="cdn-badge">
        {#if node.props?.cdn}☁️ CDN: <b>{node.props.cdn}</b>{/if}
        {#if node.props?.waf}🛡️ WAF{/if}
      </div>
    {/if}

    <p class="desc">{TYPE_DESC[node.type] ?? "Найденный элемент."}</p>

    {#if node.type === "cve" && node.props?.summary}
      <div class="cve-box">
        <div class="cve-meta">
          <span class="sev {String(node.props.severity).toLowerCase()}">{severityName(node.props.severity)}</span>
          {#if node.props.score}<span class="score">CVSS {node.props.score}</span>{/if}
        </div>
        {#if node.props.known_exploited}
          <div class="kev-warn">⚠️ Активно эксплуатируется (CISA KEV)</div>
        {/if}
        {#if node.props.epss != null}
          <div class="score">EPSS: {(Number(node.props.epss) * 100).toFixed(1)}% (вероятность эксплуатации в ближайшие 30 дней)</div>
        {/if}
        <p class="cve-sum">{node.props.summary}</p>
      </div>
    {/if}

    {#if node.type === "param" && candidateKinds(node).length > 0}
      <div class="cand-row">
        {#each candidateKinds(node) as k}<span class="cand">{k}</span>{/each}
      </div>
    {/if}

    {#if node.type === "finding"}
      <div class="cve-box">
        <div class="cve-meta">
          <span class="sev {String(node.props?.severity).toLowerCase()}">{severityName(node.props?.severity)}</span>
        </div>
        {#if node.props?.description}<p class="cve-sum">{node.props.description}</p>{/if}
      </div>
    {/if}

    {#if urlForNode(node)}
      <div class="node-actions">
        <button class="primary sm" onclick={() => OpenURL(urlForNode(node)!)}>🌐 Открыть в браузере</button>
        {#if node.type === "url"}
          <button class="ghost sm" onclick={() => viewHTML(node)}>📄 Показать HTML</button>
        {/if}
      </div>
    {/if}

    <!-- The page's screenshot, right under the open / view-HTML buttons. -->
    <ShotPreview {node} />

    <NextStep {node} />

    <NotesEditor {node} />

    <table>
      <tbody>
        {#each propEntries(node) as [k, v]}
          <tr>
            <th>{k}</th>
            <td>
              {#if typeof v === "string" && /^https?:\/\//.test(v)}
                <button class="linkbtn" onclick={() => OpenURL(v)}>{v}</button>
              {:else}
                {fmt(v)}
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if propEntries(node).length === 0}
      <p class="muted">Дополнительных данных нет.</p>
    {/if}

    {#if connections.length > 0}
      <h3 class="section">Связи ({connections.length})</h3>
      <ul class="conns">
        {#each connections as c}
          <li>
            <span class="rel">{c.dir === "out" ? "→" : "←"} {c.rel}</span>
            <span class="conn-chip" data-type={c.type}>{typeName(c.type)}</span>
            <button class="linkbtn conn-label" onclick={() => (app.selected = app.view?.focusNode(c.id) ?? app.selected)}>{c.label}</button>
          </li>
        {/each}
      </ul>
    {/if}
  </aside>
{/if}

{#if pageView}
  <div class="modal-bg" role="presentation" onclick={() => (pageView = null)}>
    <div class="modal wide" role="dialog" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.key === "Escape" && (pageView = null)}>
      <div class="detail-head">
        <h2>Исходный код страницы</h2>
        <button class="ghost sm" onclick={() => (pageView = null)}>✕</button>
      </div>
      <div class="statusline">
        {#if pageLoading}Загрузка…{:else}
          HTTP <span class="code sc" style="--sc:{statusClassOf(Number(pageView.status) || null)?.color ?? '#64748b'}">{pageView.status}</span>
          {#if pageView.server}· {pageView.server}{/if}
        {/if}
      </div>
      <button class="linkbtn" onclick={() => OpenURL(pageView.url)}>{pageView.url}</button>
      <pre class="html">{pageView.body}</pre>
    </div>
  </div>
{/if}
