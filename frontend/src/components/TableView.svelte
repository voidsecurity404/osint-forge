<script lang="ts">
  import { app } from "../lib/state.svelte";
  import { statusOf, statusClassOf } from "../lib/graph";
  import { TAGS } from "../lib/api";
  import type { graph } from "../lib/models";

  let search = $state("");
  let typeFilter = $state<string>("all");

  // Recompute whenever the graph version changes.
  const nodes = $derived.by<graph.Node[]>(() => {
    app.version;
    return app.view ? app.view.allNodes() : [];
  });
  const types = $derived.by<string[]>(() => {
    const t = new Set(nodes.map((n) => n.type));
    return ["all", ...[...t].sort()];
  });
  const rows = $derived.by(() => {
    const q = search.trim().toLowerCase();
    return nodes
      .filter((n) => typeFilter === "all" || n.type === typeFilter)
      .filter((n) => !q || (n.label ?? "").toLowerCase().includes(q) || n.id.toLowerCase().includes(q))
      .sort((a, b) => a.type.localeCompare(b.type) || (a.label ?? "").localeCompare(b.label ?? ""));
  });
  // Rendering tens of thousands of rows on every live update froze the tab on
  // big scans; show the first MAX_ROWS and ask to narrow the search.
  const MAX_ROWS = 1500;
  const shown = $derived(rows.length > MAX_ROWS ? rows.slice(0, MAX_ROWS) : rows);

  function tagsOf(id: string): string[] {
    const t = app.notes[id]?.tags ?? [];
    return t.map((k) => TAGS.find((x) => x.key === k)?.icon ?? "");
  }
  function pick(n: graph.Node) {
    app.mode = "graph";
    queueMicrotask(() => {
      app.selected = app.view?.focusNode(n.id) ?? n;
    });
  }
</script>

<div class="tableview">
  <div class="table-controls">
    <input class="tsearch" type="search" placeholder="🔍 Qidirish (nom yoki id)…" bind:value={search} />
    <select bind:value={typeFilter}>
      {#each types as t}
        <option value={t}>{t === "all" ? "Barcha turlar" : t} ({t === "all" ? nodes.length : nodes.filter((n) => n.type === t).length})</option>
      {/each}
    </select>
    <span class="muted">{rows.length} ta{#if rows.length > shown.length} · birinchi {shown.length} tasi ko'rsatilgan — qidiruv yoki tur bilan toraytiring{/if}</span>
  </div>
  <div class="table-scroll">
    <table class="grid">
      <thead>
        <tr><th>Tur</th><th>Nom</th><th>Status</th><th>Teg</th><th>Qo'shimcha</th></tr>
      </thead>
      <tbody>
        {#each shown as n (n.id)}
          <tr onclick={() => pick(n)}>
            <td><span class="type-chip" data-type={n.type}>{n.type}</span></td>
            <td class="tname">{n.label}</td>
            <td>
              {#if statusOf(n) != null}
                {@const sc = statusClassOf(statusOf(n))}
                <span class="code sc" style="--sc:{sc?.color}">{statusOf(n)}</span>
              {/if}
            </td>
            <td>{tagsOf(n.id).join(" ")}</td>
            <td class="tmeta">{n.props?.candidate ?? n.props?.severity ?? n.props?.version ?? n.props?.service ?? ""}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if rows.length === 0}<p class="muted center">Hech narsa topilmadi.</p>{/if}
  </div>
</div>
