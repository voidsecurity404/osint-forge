<script lang="ts">
  // Screenshot of the page behind a node, shown in the detail panel right under
  // «Открыть в браузере / Показать HTML».
  //  - URL nodes: the stored screenshot, or one taken on demand. Pages the scan
  //    already requested are captured automatically; pages it never touched
  //    (wayback, sitemap, JS) need a click, so a passive scan stays passive.
  //  - Host / port / finding nodes: the screenshot of a linked URL, if any.
  import { untrack } from "svelte";
  import { app, errMsg } from "../lib/state.svelte";
  import { ApiError, CaptureScreenshot, screenshotURL } from "../lib/api";
  import type { graph } from "../lib/models";

  let { node }: { node: graph.Node } = $props();

  type State =
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "ready"; path: string; takenAt: string }
    | { kind: "offer"; msg: string }
    | { kind: "error"; msg: string; retry: boolean };

  let st = $state<State>({ kind: "idle" });
  let ctrl: AbortController | null = null;
  let brokenLinked = $state(""); // path of a linked image that failed to load

  const pageUrl = $derived(node.type === "url" ? node.id.replace(/^url:/, "") : null);

  // Non-URL nodes: a neighbouring URL that already has a screenshot.
  const linked = $derived.by<{ url: string; path: string } | null>(() => {
    app.version; // recompute as the graph changes
    if (node.type === "url" || !app.view) return null;
    for (const nb of app.view.neighborsOf(node.id)) {
      if (nb.type !== "url") continue;
      const p = app.view.rawOf(nb.id)?.props?.screenshot;
      if (typeof p === "string" && p) return { url: nb.id.replace(/^url:/, ""), path: p };
    }
    return null;
  });

  async function load(url: string, opts: { force?: boolean; auto?: boolean }) {
    ctrl?.abort();
    const c = new AbortController();
    ctrl = c;
    st = { kind: "loading" };
    try {
      const s = await CaptureScreenshot(url, opts, c.signal);
      if (c.signal.aborted) return;
      st = { kind: "ready", path: s.path, takenAt: s.takenAt };
    } catch (e) {
      if (c.signal.aborted) return; // another node was opened meanwhile
      if (e instanceof ApiError && e.status === 409) st = { kind: "offer", msg: cap(e.message) };
      else {
        // 501 = no browser installed, 404 = page not in the server's graph:
        // retrying cannot help there.
        const final = e instanceof ApiError && (e.status === 501 || e.status === 404);
        st = { kind: "error", msg: cap(errMsg(e)), retry: !final };
      }
    }
  }

  // Server messages follow Go style (lower-case start); show them as sentences.
  const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

  // Re-run only when a different page is opened (not on every live update).
  $effect(() => {
    const url = pageUrl;
    untrack(() => {
      if (url) load(url, { auto: true });
      else {
        ctrl?.abort();
        st = { kind: "idle" };
      }
    });
    return () => ctrl?.abort();
  });

  function ago(iso: string): string {
    const t = Date.parse(iso);
    if (isNaN(t)) return "";
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return "только что";
    if (s < 3600) return `${Math.round(s / 60)} мин. назад`;
    if (s < 86400) return `${Math.round(s / 3600)} ч. назад`;
    if (s < 7 * 86400) return `${Math.round(s / 86400)} дн. назад`;
    return new Date(t).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
  }
</script>

{#if pageUrl}
  <div class="shot-box" data-state={st.kind}>
    {#if st.kind === "loading"}
      <div class="shot-frame shot-msg">
        <span class="spinner" aria-hidden="true"></span>
        <span>Снимаем скриншот страницы…</span>
        <small>обычно меньше секунды, на медленных сайтах — несколько секунд</small>
      </div>
    {:else if st.kind === "ready"}
      {@const src = screenshotURL(st.path, st.takenAt)}
      <a class="shot-frame" href={src} target="_blank" rel="noopener" title="Открыть в полном размере">
        <img
          {src}
          alt="Скриншот страницы"
          onerror={() => (st = { kind: "error", msg: "Изображение не загрузилось", retry: true })}
        />
      </a>
      <div class="shot-meta">
        <span>📸 {ago(st.takenAt)}</span>
        <button class="linkbtn" onclick={() => load(pageUrl!, { force: true })} title="Снять страницу заново">🔄 Обновить</button>
      </div>
    {:else if st.kind === "offer"}
      <div class="shot-frame shot-msg">
        <span>{st.msg}</span>
        <button class="ghost sm" onclick={() => load(pageUrl!, {})}>📸 Сделать скриншот</button>
      </div>
    {:else if st.kind === "error"}
      <div class="shot-frame shot-msg">
        <span>❌ {st.msg}</span>
        {#if st.retry}<button class="ghost sm" onclick={() => load(pageUrl!, { force: true })}>↻ Повторить</button>{/if}
      </div>
    {/if}
  </div>
{:else if linked && brokenLinked !== linked.path}
  <div class="shot-box" data-state="linked">
    <a class="shot-frame" href={screenshotURL(linked.path)} target="_blank" rel="noopener" title="Открыть в полном размере">
      <!-- The file may have been deleted from the cache: hide instead of a broken image. -->
      <img src={screenshotURL(linked.path)} alt="Скриншот страницы" onerror={() => (brokenLinked = linked!.path)} />
    </a>
    <div class="shot-meta"><span class="shot-url">📸 {linked.url}</span></div>
  </div>
{/if}
