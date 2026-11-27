<script lang="ts">
  import { app } from "../lib/state.svelte";

  let showLogs = $state(true);
</script>

<footer>
  <div class="status">
    <span class="dot" class:on={app.running}></span>
    {#if app.progress}
      <strong>{app.progress.phase}</strong>
      {#if app.progress.running}· {app.progress.running}{/if}
      · {app.progress.done}/{app.progress.total}
    {:else if app.running}
      <strong>Skanlanmoqda…</strong>
    {:else}
      Tayyor
    {/if}
    <span class="sep">|</span>
    <span>{app.liveCounts.nodes} tugun · {app.liveCounts.edges} bog'lanish</span>
    {#if app.layoutBusy}
      <span class="sep">|</span><span class="layout-busy" title="Tugunlar bir-biriga tegmaydigan qilib joylashtirilmoqda (fonda, interfeys bloklanmaydi)">🧭 Graf joylashtirilmoqda…</span>
    {/if}
    {#if !app.nmapOk}
      <span class="sep">|</span><span class="warn">nmap o'rnatilmagan — fallback skaner</span>
    {/if}
    <span class="grow"></span>
    <button class="ghost sm" onclick={() => (showLogs = !showLogs)}>
      {showLogs ? "Loglarni yashirish" : "Loglar"}
    </button>
  </div>
  {#if showLogs}
    <div class="logs">
      {#each app.logs as l}
        <div class="log {l.level}"><span class="src">{l.source}</span> {l.message}</div>
      {/each}
      {#if app.logs.length === 0}<div class="muted">Loglar shu yerda ko'rinadi…</div>{/if}
    </div>
  {/if}
</footer>
