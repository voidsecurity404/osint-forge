<script lang="ts">
  import { untrack } from "svelte";
  import { app, errMsg } from "../lib/state.svelte";
  import { NoteSave, TAGS } from "../lib/api";
  import type { graph } from "../lib/models";

  let { node }: { node: graph.Node } = $props();

  const note = $derived(app.notes[node.id] ?? {});
  let text = $state("");
  let saving = $state(false);
  let savedAt = $state("");

  // Reset the editor when another node is selected.
  // Only depends on node.id: saving (which updates app.notes) must not reset it.
  $effect(() => {
    const id = node.id;
    untrack(() => {
      text = app.notes[id]?.text ?? "";
      savedAt = "";
    });
  });

  async function save(tags: string[], body: string) {
    // Notes belong to the graph on screen, not to whatever is typed in the
    // target box right now.
    const target = app.graphTarget || app.target;
    if (!target.trim()) {
      app.flash("ℹ️ Avval skanlang yoki tarixdan scan oching");
      return;
    }
    saving = true;
    try {
      const n = await NoteSave(target, node.id, tags, body);
      const next = { ...app.notes };
      if (!n.tags?.length && !n.text) delete next[node.id];
      else next[node.id] = n;
      app.notes = next;
      app.view?.setTags(app.notes);
      savedAt = new Date().toLocaleTimeString();
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    } finally {
      saving = false;
    }
  }

  function toggle(tag: string) {
    const cur = note.tags ?? [];
    const tags = cur.includes(tag) ? cur.filter((t) => t !== tag) : [...cur, tag];
    save(tags, text);
  }

  function saveText() {
    if ((note.text ?? "") !== text.trim()) save(note.tags ?? [], text);
  }
</script>

<div class="notes">
  <h3 class="section">📝 Eslatma va teglar</h3>
  <div class="tag-row">
    {#each TAGS as t}
      <button class="tag-btn tag-{t.key}" class:on={note.tags?.includes(t.key)} onclick={() => toggle(t.key)} disabled={saving}>
        {t.icon} {t.label}
      </button>
    {/each}
  </div>
  <textarea
    bind:value={text}
    onblur={saveText}
    rows="3"
    placeholder="Masalan: 403 bypass X-Original-URL bilan ishladi; payload…"
  ></textarea>
  <div class="note-meta">
    {#if saving}Saqlanmoqda…{:else if savedAt}✅ Saqlandi {savedAt}{:else}Maydondan chiqqanda avtomatik saqlanadi{/if}
  </div>
</div>
