// Graph-level actions shared by several components.
import { app, errMsg } from "./state.svelte";
import { HistoryCompare, HistoryOpen, Snapshot, Status } from "./api";
import type { graph } from "./models";

/** Replace the whole graph with a delta and settle the layout. */
export function showGraph(d: graph.Delta | null | undefined) {
  const v = app.view;
  if (!v) return;
  app.selected = null;
  app.statusFilter = null;
  v.reset();
  if (d) v.apply(d);
  app.refreshCounts();
  v.finalize();
}

/** Visual diff of two stored scans (empty ids = latest vs the one before). */
export async function compareScans(target: string, from = "", to = "") {
  if (app.running) {
    app.flash("ℹ️ Scan davom etmoqda — tugagach solishtiring");
    return;
  }
  if (!target.trim()) {
    app.flash("ℹ️ Avval nishonni skanlang yoki tarixdan oching");
    return;
  }
  try {
    const c = await HistoryCompare(target, from, to);
    if (!c.from) {
      app.flash("ℹ️ Oldingi scan topilmadi — taqqoslash uchun yana bir marta skanlang");
      return;
    }
    showGraph(c.graph);
    app.view?.markDiff(c.added ?? [], c.removed ?? []);
    app.graphTarget = c.target || target;
    app.loadNotes(app.graphTarget);
    app.diff = { target: c.target, from: c.from, to: c.to, added: c.added?.length ?? 0, removed: c.removed?.length ?? 0 };
    app.mode = "graph";
  } catch (e) {
    app.flash("❌ " + errMsg(e));
  }
}

/** Leave diff mode: redraw the server's current graph. */
export async function exitDiff() {
  app.diff = null;
  app.view?.clearDiff();
  try {
    const [snap, st] = await Promise.all([Snapshot(), Status()]);
    showGraph(snap);
    app.graphTarget = st.target ?? "";
    app.loadNotes();
  } catch (e) {
    app.flash("❌ " + errMsg(e));
  }
}

/** Make a stored scan the current graph (server side too, so exports match). */
export async function openScan(target: string, id: string) {
  try {
    const d = await HistoryOpen(target, id);
    app.diff = null;
    app.target = target;
    app.graphTarget = target;
    app.logs = [];
    app.progress = null;
    app.timings = [];
    showGraph(d);
    app.loadNotes(target);
    app.flash("📂 Scan ochildi: " + target);
  } catch (e) {
    app.flash("❌ " + errMsg(e));
  }
}

/** Short local date-time for history lists. */
export function when(iso: string): string {
  const d = new Date(iso);
  return isNaN(+d) ? iso : d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
}
