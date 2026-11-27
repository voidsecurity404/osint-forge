<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { statusOf, statusClassOf, type Neighbor } from "../lib/graph";
  import { OpenURL, FetchPage } from "../lib/api";
  import type { graph } from "../lib/models";
  import NotesEditor from "./NotesEditor.svelte";
  import NextStep from "./NextStep.svelte";
  import ShotPreview from "./ShotPreview.svelte";

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
    param: "URL parametri — arxiv va JS'dan yig'ilgan. Turi (SQLi, XSS, redirect…) qo'lda tekshirish uchun nomzod ekanini bildiradi.",
    bucket: "Bulut xotira (S3 / GCS / Azure) — domen nomidan taxmin qilingan va mavjudligi tekshirilgan.",
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
      pageView = { url: u, status: 0, body: "Xatolik: " + String(e?.message ?? e), title: "", server: "" };
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
      <span class="type-chip" data-type={node.type}>{node.type}</span>
      <button class="ghost sm" onclick={close} aria-label="Yopish">✕</button>
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

    <p class="desc">{TYPE_DESC[node.type] ?? "Topilgan element."}</p>

    {#if node.type === "cve" && node.props?.summary}
      <div class="cve-box">
        <div class="cve-meta">
          <span class="sev {String(node.props.severity).toLowerCase()}">{node.props.severity}</span>
          {#if node.props.score}<span class="score">CVSS {node.props.score}</span>{/if}
        </div>
        {#if node.props.known_exploited}
          <div class="kev-warn">⚠️ Faol ekspluatatsiya qilinmoqda (CISA KEV)</div>
        {/if}
        {#if node.props.epss != null}
          <div class="score">EPSS: {(Number(node.props.epss) * 100).toFixed(1)}% (30 kun ichida ekspluatatsiya ehtimoli)</div>
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
          <span class="sev {String(node.props?.severity).toLowerCase()}">{node.props?.severity}</span>
        </div>
        {#if node.props?.description}<p class="cve-sum">{node.props.description}</p>{/if}
      </div>
    {/if}

    {#if urlForNode(node)}
      <div class="node-actions">
        <button class="primary sm" onclick={() => OpenURL(urlForNode(node)!)}>🌐 Brauzerda ochish</button>
        {#if node.type === "url"}
          <button class="ghost sm" onclick={() => viewHTML(node)}>📄 HTML ko'rish</button>
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
      <p class="muted">Qo'shimcha ma'lumot yo'q.</p>
    {/if}

    {#if connections.length > 0}
      <h3 class="section">Bog'lanishlar ({connections.length})</h3>
      <ul class="conns">
        {#each connections as c}
          <li>
            <span class="rel">{c.dir === "out" ? "→" : "←"} {c.rel}</span>
            <span class="conn-chip" data-type={c.type}>{c.type}</span>
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
        <h2>Sahifa manbasi</h2>
        <button class="ghost sm" onclick={() => (pageView = null)}>✕</button>
      </div>
      <div class="statusline">
        {#if pageLoading}Yuklanmoqda…{:else}
          HTTP <span class="code sc" style="--sc:{statusClassOf(Number(pageView.status) || null)?.color ?? '#64748b'}">{pageView.status}</span>
          {#if pageView.server}· {pageView.server}{/if}
        {/if}
      </div>
      <button class="linkbtn" onclick={() => OpenURL(pageView.url)}>{pageView.url}</button>
      <pre class="html">{pageView.body}</pre>
    </div>
  </div>
{/if}
