<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { stageName } from "../lib/i18n";

  let showLogs = $state(true);
</script>

<footer>
  <div class="status">
    <span class="dot" class:on={app.running}></span>
    {#if app.progress}
      <strong>{stageName(app.progress.phase)}</strong>
      {#if app.progress.running}· {app.progress.running}{/if}
      · {app.progress.done}/{app.progress.total}
    {:else if app.running}
      <strong>Сканирование…</strong>
    {:else}
      Готово
    {/if}
    <span class="sep">|</span>
    <span>узлов: {app.liveCounts.nodes} · связей: {app.liveCounts.edges}</span>
    {#if app.layoutBusy}
      <span class="sep">|</span><span class="layout-busy" title="Узлы раскладываются так, чтобы не перекрываться (в фоне, интерфейс не блокируется)">🧭 Раскладка графа…</span>
    {/if}
    {#if !app.nmapOk}
      <span class="sep">|</span><span class="warn">nmap не установлен — резервный сканер</span>
    {/if}
    <span class="grow"></span>
    <button class="ghost sm" onclick={() => (showLogs = !showLogs)}>
      {showLogs ? "Скрыть журнал" : "Журнал"}
    </button>
  </div>
  {#if showLogs}
    <div class="logs">
      {#each app.logs as l}
        <div class="log {l.level}"><span class="src">{l.source}</span> {l.message}</div>
      {/each}
      {#if app.logs.length === 0}<div class="muted">Здесь появится журнал…</div>{/if}
    </div>
  {/if}
</footer>
