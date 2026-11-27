// Shared, reactive UI state (Svelte 5 runes). Every component imports `app`.
import type { GraphView } from "./graph";
import type { core, graph } from "./models";
import { NotesLoad, type Note, type SourceTiming } from "./api";

export type Mode = "graph" | "table" | "gallery";
export type Drawer = null | "history" | "monitor" | "sources";

export interface DiffInfo {
  target: string;
  from: string;
  to: string;
  added: number;
  removed: number;
}

class AppState {
  /** The Cytoscape wrapper (set once in App.svelte onMount; not reactive). */
  view: GraphView | null = null;

  /** What is typed in the target box (may differ from the graph on screen). */
  target = $state("");
  /**
   * The target of the graph currently shown — set when a scan starts or a stored
   * scan is opened. Notes, exports and diffs use THIS, never the input box:
   * typing a new name after a scan used to file tags under the wrong target.
   */
  graphTarget = $state("");
  consent = $state(false);
  running = $state(false);
  /** «Остановить» was pressed; the server is still winding the scan down. */
  cancelling = $state(false);
  nmapOk = $state(false);
  /** The layout worker is arranging the graph (big graphs take a while). */
  layoutBusy = $state(false);
  error = $state("");

  selected = $state<graph.Node | null>(null);
  logs = $state<core.LogLine[]>([]);
  progress = $state<core.Progress | null>(null);
  timings = $state<SourceTiming[]>([]);

  liveCounts = $state({ nodes: 0, edges: 0 });
  statusCounts = $state<Record<string, number>>({});
  statusFilter = $state<string | null>(null);
  /** Bumped whenever graph content changes, so derived views (table, gallery) recompute. */
  version = $state(0);

  mode = $state<Mode>("graph");
  drawer = $state<Drawer>(null);
  diff = $state<DiffInfo | null>(null);
  toast = $state("");
  private toastTimer: number | undefined;

  flash(msg: string) {
    this.toast = msg;
    clearTimeout(this.toastTimer);
    this.toastTimer = window.setTimeout(() => (this.toast = ""), 4000);
  }

  refreshCounts() {
    if (!this.view) return;
    this.liveCounts = this.view.counts();
    this.statusCounts = this.view.statusCounts();
    this.version++;
    // Keep the open detail panel fresh when the selected node's props change
    // mid-scan (e.g. a URL gains a screenshot, a service gains a CVE).
    if (this.selected) {
      const fresh = this.view.rawOf(this.selected.id);
      if (fresh && fresh !== this.selected) this.selected = fresh;
    }
  }

  /** Pentester notes of the current target, keyed by node id. */
  notes = $state<Record<string, Note>>({});

  async loadNotes(target = this.graphTarget) {
    const want = target.trim();
    try {
      const notes = (await NotesLoad(want)) ?? {};
      if (want !== this.graphTarget.trim()) return; // another graph is on screen now
      this.notes = notes;
    } catch {
      this.notes = {};
    }
    this.view?.setTags(this.notes);
  }

  toggleDrawer(d: Exclude<Drawer, null>) {
    this.drawer = this.drawer === d ? null : d;
  }
}

export const app = new AppState();

export function errMsg(e: any): string {
  return String(e?.message ?? e);
}
