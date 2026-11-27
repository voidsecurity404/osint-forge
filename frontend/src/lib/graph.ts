// Cytoscape wrapper. Renders an Obsidian-like graph with a LIVE, continuously
// animating force simulation (cola.js). Unlike a batch layout (fcose), cola runs
// asynchronously a little per animation frame, so nodes glide into place while a
// scan streams in and the UI never freezes.
import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from "cytoscape";
// @ts-ignore - cytoscape-cola ships no types
import cola from "cytoscape-cola";
import type { graph } from "./models";
import { nodeBox } from "./layoutBox";

cytoscape.use(cola);

const TYPE_COLOR: Record<string, string> = {
  ip: "#f59e0b",
  domain: "#38bdf8",
  subdomain: "#60a5fa",
  port: "#a78bfa",
  service: "#34d399",
  technology: "#f472b6",
  certificate: "#fbbf24",
  asn: "#fb923c",
  whois_org: "#94a3b8",
  url: "#22d3ee",
  email: "#e879f9",
  cve: "#ef4444",
  finding: "#fb7185",
  param: "#2dd4bf",
  bucket: "#fbbf24",
};
const FALLBACK = "#64748b";

function severityColor(sev: string): string {
  switch (sev.toLowerCase()) {
    case "critical": return "#dc2626";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#84cc16";
    case "info": return "#38bdf8";
  }
  return "";
}

/** HTTP status classes: node colour + legend entry. Order = legend order. */
export interface StatusClass {
  key: string;
  label: string;
  hint: string;
  color: string;
}
export const STATUS_CLASSES: StatusClass[] = [
  { key: "2xx", label: "2xx", hint: "OK — страница открывается", color: "#22c55e" },
  { key: "3xx", label: "3xx", hint: "Редирект — перенаправляет на другой адрес", color: "#3b82f6" },
  { key: "auth", label: "401/403", hint: "Нужна авторизация / запрещено — защищённый ресурс", color: "#a855f7" },
  { key: "4xx", label: "4xx", hint: "Ошибка клиента (404 и т. п.)", color: "#eab308" },
  { key: "5xx", label: "5xx", hint: "Ошибка сервера — признак неисправности", color: "#ef4444" },
  { key: "other", label: "другое", hint: "1xx или нестандартный код", color: "#94a3b8" },
];
const STATUS_BY_KEY = new Map(STATUS_CLASSES.map((c) => [c.key, c]));

/** HTTP status code of a node (from the http probe / fuzzer), or null. */
export function statusOf(n: graph.Node | null | undefined): number | null {
  const v = n?.props?.status;
  if (v == null || v === "") return null;
  const code = typeof v === "number" ? v : parseInt(String(v), 10);
  return Number.isFinite(code) && code > 0 ? code : null;
}

/** Status class key for a code: 2xx, 3xx, auth (401/403), 4xx, 5xx, other. */
export function statusClassOf(code: number | null): StatusClass | null {
  if (code == null) return null;
  if (code === 401 || code === 403) return STATUS_BY_KEY.get("auth")!;
  if (code >= 200 && code < 300) return STATUS_BY_KEY.get("2xx")!;
  if (code >= 300 && code < 400) return STATUS_BY_KEY.get("3xx")!;
  if (code >= 400 && code < 500) return STATUS_BY_KEY.get("4xx")!;
  if (code >= 500 && code < 600) return STATUS_BY_KEY.get("5xx")!;
  return STATUS_BY_KEY.get("other")!;
}

export function colorFor(n: graph.Node): string {
  if (n.type === "cve" || n.type === "finding") {
    const col = severityColor(String(n.props?.severity ?? ""));
    if (col) return col;
  }
  // Anything that answered an HTTP request is coloured by its status code.
  const sc = statusClassOf(statusOf(n));
  if (sc) return sc.color;
  return TYPE_COLOR[n.type] ?? FALLBACK;
}

function sizeFor(n: graph.Node): number {
  if (n.props?.root) return 50;
  switch (n.type) {
    case "ip":
    case "domain":
      return 36;
    case "subdomain":
    case "service":
      return 26;
    default:
      return 16;
  }
}

// Edges that keep a child tight to its parent (service↔cve/port/tech/path).
const SHORT_EDGES = new Set(["has_cve", "runs_service", "has_technology", "has_port", "path", "finding"]);
const GOLDEN = 2.399963229728653;

/** A connection summary surfaced to the detail panel. */
export interface Neighbor {
  id: string;
  type: string;
  label: string;
  rel: string;
  dir: "out" | "in";
}

export class GraphView {
  private cy: Core;
  private onSelect: (n: graph.Node | null) => void;
  private layout: any = null;
  private relaxTimer: number | null = null;
  private container: HTMLElement;
  private ro: ResizeObserver | null = null;
  /** Primary pentester tag per node id (drives the node ring colour). */
  private tags = new Map<string, string>();

  /** Called on any tap inside the graph (node or background). */
  onTap: (() => void) | null = null;

  constructor(container: HTMLElement, onSelect: (n: graph.Node | null) => void) {
    this.onSelect = onSelect;
    this.container = container;
    this.cy = cytoscape({
      container,
      wheelSensitivity: 1.0,
      minZoom: 0.02,
      maxZoom: 4,
      // Keep edges visible always. hideEdgesOnViewport produced a thick gray wedge
      // artifact while the cola layout animated (continuous viewport motion), and
      // the user wants to see connections during panning.
      textureOnViewport: false,
      hideEdgesOnViewport: false,
      motionBlur: false,
      pixelRatio: 1,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            width: "data(size)",
            height: "data(size)",
            label: "data(label)",
            color: "#cbd5e1",
            "font-size": 10,
            "min-zoomed-font-size": 8,
            "text-valign": "bottom",
            "text-margin-y": 3,
            "text-wrap": "ellipsis",
            "text-max-width": "140px",
            "border-width": 0,
            "overlay-opacity": 0,
          },
        },
        { selector: "node.focus", style: { "border-width": 4, "border-color": "#e2e8f0" } },
        // CISA KEV (actively exploited) CVEs get a bright red ring.
        { selector: "node[kev = 1]", style: { "border-width": 5, "border-color": "#fecaca" } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#3a4a63",
            // haystack = a plain straight segment between node centres (cheapest
            // edge type to render). Low opacity keeps the many edges converging
            // on the root hub readable as a soft fan.
            opacity: 0.4,
            "overlay-opacity": 0,
          },
        },
        { selector: "edge.focus", style: { "line-color": "#93c5fd", opacity: 1, width: 2 } },
        // History diff: new since the previous scan / gone since then.
        { selector: "node.added", style: { "border-width": 5, "border-color": "#22c55e" } },
        { selector: "node.removed", style: { "border-width": 3, "border-color": "#ef4444", "border-style": "dashed", "background-opacity": 0.35 } },
        { selector: "edge.removed", style: { "line-color": "#ef4444", "line-style": "dashed", opacity: 0.6 } },
        // Pentester tags (notes): vulnerable / checked / false positive / interesting.
        { selector: "node[tag = 'vuln']", style: { "border-width": 4, "border-color": "#f43f5e" } },
        { selector: "node[tag = 'checked']", style: { "border-width": 3, "border-color": "#a3e635" } },
        { selector: "node[tag = 'interesting']", style: { "border-width": 3, "border-color": "#fde047" } },
        { selector: "node[tag = 'fp']", style: { opacity: 0.35 } },
        // Search / type filter.
        { selector: ".hidden", style: { display: "none" } },
        { selector: "node.match", style: { "border-width": 4, "border-color": "#f8fafc" } },
        { selector: ".dim", style: { opacity: 0.07 } },
      ],
      elements: [],
    });

    // Cytoscape has no built-in double-tap event, so detect it manually: a second
    // tap on the same node within 320ms is a double-click (opens the panel); a
    // single tap just highlights the node's connections.
    this.cy.on("tap", () => this.onTap?.());
    this.cy.on("grab", "node", (e) => this.moved.add(e.target.id()));
    let lastId = "";
    let lastTime = 0;
    this.cy.on("tap", "node", (e) => {
      // Freeze the live simulation on interaction so nodes don't move under the
      // cursor — makes a second tap (double-click) land reliably, during a scan too.
      if (this.layout) this.layout.stop();
      this.interactUntil = Date.now() + 1500; // hold still ~1.5s for double-click
      const id = e.target.id();
      const now = Date.now();
      if (id === lastId && now - lastTime < 450) {
        this.onSelect(e.target.data("raw") as graph.Node); // double → panel
        lastId = "";
        lastTime = 0;
      } else {
        this.highlight(e.target); // single → highlight
        lastId = id;
        lastTime = now;
      }
    });
    this.cy.on("tap", (e) => {
      if (e.target === this.cy) {
        this.clearHighlight();
        this.onSelect(null);
      }
    });

    // The container may be 0-sized or resize after cytoscape initialises (common
    // in a freshly-loaded webview). Without cy.resize() the renderer caches a
    // wrong size and draws nodes outside the visible area — the "graph is empty /
    // nodes appear somewhere else" bug. A ResizeObserver keeps it correct and
    // re-frames the content whenever the viewport changes size.
    this.ro = new ResizeObserver(() => {
      this.cy.resize();
      if (this.cy.nodes().length > 0) this.frameContent();
    });
    this.ro.observe(container);
  }

  private highlight(node: NodeSingular) {
    const hood = node.closedNeighborhood();
    this.cy.batch(() => {
      this.cy.elements().addClass("dim").removeClass("focus");
      hood.removeClass("dim");
      hood.addClass("focus");
    });
  }
  private clearHighlight() {
    this.cy.batch(() => this.cy.elements().removeClass("dim focus"));
  }

  /** Neighbours of a node, for the detail panel's "Connections" section. */
  neighborsOf(id: string): Neighbor[] {
    const node = this.cy.getElementById(id);
    if (node.empty()) return [];
    const out: Neighbor[] = [];
    node.connectedEdges().forEach((e: any) => {
      const isOut = e.source().id() === id;
      const other = isOut ? e.target() : e.source();
      const raw = other.data("raw") as graph.Node;
      out.push({
        id: other.id(),
        type: raw?.type ?? other.data("type"),
        label: raw?.label ?? other.data("label"),
        rel: e.data("label"),
        dir: isOut ? "out" : "in",
      });
    });
    out.sort((a, b) => a.rel.localeCompare(b.rel));
    return out;
  }

  /**
   * Diagnostics: how many visible node pairs overlap — bodies (circles) and
   * labels (text boxes). Spatial hashing keeps it O(n) for big graphs.
   */
  overlapStats(): { nodes: number; bodyPairs: number; labelPairs: number } {
    const boxes = (includeLabels: boolean) =>
      this.cy.nodes(":visible").map((n: any) => {
        const b = includeLabels
          ? n.boundingBox({ includeNodes: false, includeEdges: false, includeLabels: true })
          : n.boundingBox({ includeLabels: false, includeOverlays: false });
        return b;
      });
    const count = (bs: any[]) => {
      const cell = 60;
      const grid = new Map<string, number[]>();
      bs.forEach((b, i) => {
        if (!(b.w > 0)) return;
        for (let x = Math.floor(b.x1 / cell); x <= Math.floor(b.x2 / cell); x++)
          for (let y = Math.floor(b.y1 / cell); y <= Math.floor(b.y2 / cell); y++) {
            const k = x + "," + y;
            const l = grid.get(k);
            if (l) l.push(i);
            else grid.set(k, [i]);
          }
      });
      const seen = new Set<string>();
      let pairs = 0;
      for (const l of grid.values())
        for (let a = 0; a < l.length; a++)
          for (let c = a + 1; c < l.length; c++) {
            const i = l[a], j = l[c];
            const k = i < j ? i + ":" + j : j + ":" + i;
            if (seen.has(k)) continue;
            seen.add(k);
            const p = bs[i], q = bs[j];
            // 2px slack: touching is fine, overlapping is not
            if (p.x1 + 2 < q.x2 && q.x1 + 2 < p.x2 && p.y1 + 2 < q.y2 && q.y1 + 2 < p.y2) pairs++;
          }
      return pairs;
    };
    return { nodes: this.cy.nodes(":visible").length, bodyPairs: count(boxes(false)), labelPairs: count(boxes(true)) };
  }

  /** True while a layout simulation is still moving nodes. */
  isLayoutRunning(): boolean {
    return this.layoutActive || this.workerBusy || this.workerQueued !== null;
  }

  /** Live element counts, for the footer. */
  counts(): { nodes: number; edges: number } {
    return { nodes: this.cy.nodes().length, edges: this.cy.edges().length };
  }

  /** Apply pentester tags: the most important tag of each node colours its ring. */
  setTags(notes: Record<string, { tags?: string[] }>) {
    const order = ["vuln", "interesting", "checked", "fp"];
    this.tags.clear();
    for (const [id, n] of Object.entries(notes)) {
      const t = order.find((o) => n.tags?.includes(o));
      if (t) this.tags.set(id, t);
    }
    this.cy.batch(() => {
      this.cy.nodes().forEach((n: any) => n.data("tag", this.tags.get(n.id()) ?? ""));
    });
  }

  /** Current raw data of one node, or null (used to refresh the open panel). */
  rawOf(id: string): graph.Node | null {
    const n = this.cy.getElementById(id);
    return n.empty() ? null : (n.data("raw") as graph.Node);
  }

  /** Every node's raw data (for the table / gallery views). */
  allNodes(): graph.Node[] {
    return this.cy.nodes().map((n: any) => n.data("raw") as graph.Node).filter(Boolean);
  }

  /** Mark a history diff: added nodes get a green ring, removed ones red/dashed. */
  markDiff(added: string[], removed: string[]) {
    this.cy.batch(() => {
      this.cy.elements().removeClass("added removed");
      for (const id of added) this.cy.getElementById(id).addClass("added");
      for (const id of removed) {
        const n = this.cy.getElementById(id);
        n.addClass("removed");
        n.connectedEdges().addClass("removed");
      }
    });
  }
  clearDiff() {
    this.cy.elements().removeClass("added removed");
  }

  /** Live graph search: hide non-matching nodes (and their now-isolated edges),
   * ring the matches. Empty query restores everything. */
  search(q: string) {
    q = q.trim().toLowerCase();
    this.cy.batch(() => {
      this.cy.elements().removeClass("hidden match");
      if (!q) return;
      const match = this.cy.nodes().filter((n: any) => {
        const raw = n.data("raw");
        return (raw?.label ?? "").toLowerCase().includes(q) || n.id().toLowerCase().includes(q);
      });
      if (match.empty()) return;
      const keep = match.union(match.connectedEdges());
      this.cy.elements().not(keep).addClass("hidden");
      match.addClass("match");
    });
    if (q) this.frameContent();
  }

  /** Select + centre a node (used by the table view and search). */
  focusNode(id: string): graph.Node | null {
    const n = this.cy.getElementById(id);
    if (n.empty()) return null;
    this.highlight(n as NodeSingular);
    this.cy.animate({ center: { eles: n }, zoom: Math.max(this.cy.zoom(), 1.1) } as any, { duration: 300 });
    return n.data("raw") as graph.Node;
  }

  /** How many nodes fall in each HTTP status class (for the legend). */
  statusCounts(): Record<string, number> {
    const out: Record<string, number> = {};
    this.cy.nodes().forEach((n: any) => {
      const k = n.data("status");
      if (k) out[k] = (out[k] ?? 0) + 1;
    });
    return out;
  }

  /** Highlight every node of one status class (plus its edges); null clears. */
  highlightStatus(key: string | null) {
    if (!key) {
      this.clearHighlight();
      return;
    }
    const nodes = this.cy.nodes().filter((n: any) => n.data("status") === key);
    const hood = nodes.union(nodes.connectedEdges());
    this.cy.batch(() => {
      this.cy.elements().addClass("dim").removeClass("focus");
      hood.removeClass("dim");
      nodes.addClass("focus");
    });
  }

  zoomBy(factor: number) {
    const z = this.cy.zoom() * factor;
    this.cy.zoom({ level: z, renderedPosition: { x: this.cy.width() / 2, y: this.cy.height() / 2 } });
  }
  fit() {
    this.frameContent();
  }

  /**
   * Resize to the real container size and frame ALL content so nothing is ever
   * off-screen. cy.fit() both zooms and centers on the bounding box of every
   * element (for a hub-and-spoke recon graph that naturally puts the root near
   * the middle). We only clamp the zoom for a tiny 1–2 node graph.
   *
   * NOTE: we deliberately do NOT hard-center on the root here. Doing so shifted
   * the pan so far that distant nodes (e.g. an ASN or whois org on a long edge)
   * fell outside the viewport — the "only the root shows, other nodes are
   * off-screen" bug.
   */
  frameContent() {
    this.cy.resize(); // pick up the true container size first
    if (this.cy.nodes().length === 0) return;
    // Guard: if the container has no real size yet (webview first layout), a fit
    // would compute a garbage transform. Skip and let the ResizeObserver re-frame.
    if (this.cy.width() < 5 || this.cy.height() < 5) return;
    // Fit all elements: shows the whole graph, centered on its bounding box.
    this.cy.fit(this.cy.elements(), 80);
    // Only a 1–2 node graph fits at a very high zoom; clamp it and re-center on
    // all elements so the clamp never pushes content off-screen.
    if (this.cy.zoom() > 1.6) {
      this.cy.zoom(1.6);
      this.cy.center(this.cy.elements());
    }
  }

  private lastFit = 0;
  /**
   * During a scan: keep a small graph fully framed on every update (so the root
   * domain is always centered and visible), and throttle re-framing to ~1.3s once
   * the graph is large so it doesn't fight the live animation.
   */
  fitDuringScan() {
    const n = this.cy.nodes().length;
    if (n <= 80) {
      this.frameContent();
      return;
    }
    const now = Date.now();
    if (now - this.lastFit < 1300) return;
    this.lastFit = now;
    this.frameContent();
  }

  private toElement(n: graph.Node): ElementDefinition {
    return {
      group: "nodes",
      data: {
        id: n.id,
        label: n.label || n.id,
        type: n.type,
        color: colorFor(n),
        size: sizeFor(n),
        kev: n.props?.known_exploited ? 1 : 0, // CISA KEV flag
        status: statusClassOf(statusOf(n))?.key ?? "", // HTTP status class
        tag: this.tags.get(n.id) ?? "", // pentester tag
        root: n.props?.root ? 1 : 0, // the scan target — kept centered
        raw: n,
      },
    };
  }

  /** Add a delta's new elements and nudge the live simulation. */
  // Edges whose endpoint node hasn't arrived yet. They are retried on every
  // apply() until both endpoints exist.
  private orphanEdges = new Map<string, graph.Edge>();

  /**
   * Add a delta's new elements and nudge the live simulation.
   *
   * ROOT CAUSE of the old "thick grey bar": cy.add() THROWS if any edge in the
   * batch references a node that doesn't exist yet. The throw happened halfway
   * through the batch, so elements already inserted were never styled — an
   * unstyled edge renders with Cytoscape's defaults (width 30px, #999, opacity 1)
   * — and the rest of the delta (nodes included) was silently lost. So: nodes are
   * added first, an edge is added only when both endpoints exist (otherwise it
   * waits in orphanEdges), and nothing here can throw out of apply().
   */
  apply(delta: graph.Delta) {
    const newIds: string[] = [];
    const nodeDefs: ElementDefinition[] = [];
    const seen = new Set<string>();
    for (const n of delta.nodes ?? []) {
      if (!n || !n.id || seen.has(n.id)) continue;
      seen.add(n.id);
      const ex = this.cy.getElementById(n.id);
      if (ex.empty()) {
        nodeDefs.push(this.toElement(n));
        newIds.push(n.id);
      } else {
        ex.data("raw", n);
        ex.data("color", colorFor(n));
        ex.data("kev", n.props?.known_exploited ? 1 : 0);
        ex.data("status", statusClassOf(statusOf(n))?.key ?? "");
        if (n.label) ex.data("label", n.label);
      }
    }

    for (const e of delta.edges ?? []) {
      if (!e || !e.id || !e.source || !e.target) continue;
      if (e.source === e.target) continue; // haystack edges can't draw loops
      this.orphanEdges.set(e.id, e);
    }

    if (nodeDefs.length > 0) this.safeAdd(nodeDefs);

    // Edges (new ones + any still waiting) whose endpoints now both exist.
    const edgeDefs: ElementDefinition[] = [];
    for (const [id, e] of this.orphanEdges) {
      if (!this.cy.getElementById(id).empty()) {
        this.orphanEdges.delete(id);
        continue;
      }
      if (this.cy.getElementById(e.source).empty() || this.cy.getElementById(e.target).empty()) continue;
      this.orphanEdges.delete(id);
      edgeDefs.push({ group: "edges", data: { id: e.id, source: e.source, target: e.target, label: e.label } });
    }
    if (edgeDefs.length > 0) this.safeAdd(edgeDefs);

    if (nodeDefs.length === 0 && edgeDefs.length === 0) return;
    // IMPORTANT: place nodes AFTER cy.add has fully applied (not inside cy.batch).
    // Inside a batch, cytoscape defers index updates, so node.neighborhood() would
    // return empty and every node would collapse onto the origin — leaving the whole
    // graph piled at one point with only the root visible.
    for (const id of newIds) {
      const node = this.cy.getElementById(id);
      if (!node.empty()) this.placeNode(node as NodeSingular);
    }
    if (newIds.length > 0) this.dirty = true;
    this.scheduleRelax();
  }

  /**
   * cy.add() that can never leave half-inserted, unstyled elements behind: on a
   * failure the elements are added one at a time so a single bad element can't
   * take down the rest, and a forced style refresh repairs anything partial.
   */
  private safeAdd(defs: ElementDefinition[]) {
    try {
      this.cy.add(defs);
      return;
    } catch (err) {
      console.warn("graph: batch add failed, retrying one by one", err);
    }
    for (const d of defs) {
      if (!this.cy.getElementById(String(d.data.id)).empty()) continue;
      try {
        this.cy.add(d);
      } catch (err) {
        console.warn("graph: skipped element", d.data.id, err);
      }
    }
    this.cy.style().update();
  }

  /** Seed a new node near an already-placed neighbour so cola starts it well. */
  private placeNode(node: NodeSingular) {
    let anchor: NodeSingular | null = null;
    node.neighborhood("node").forEach((nb: any) => {
      if (!anchor && nb.id() !== node.id() && nb.scratch("_placed")) anchor = nb as NodeSingular;
    });
    if (!anchor) {
      node.position({ x: (Math.random() - 0.5) * 120, y: (Math.random() - 0.5) * 120 });
      node.scratch("_placed", true);
      return;
    }
    const a = anchor as NodeSingular;
    const kids = ((a.scratch("_kids") as number) || 0) + 1;
    a.scratch("_kids", kids);
    const ang = kids * GOLDEN;
    const r = 70 + 22 * Math.sqrt(kids);
    const ap = a.position();
    node.position({ x: ap.x + r * Math.cos(ang), y: ap.y + r * Math.sin(ang) });
    node.scratch("_placed", true);
  }

  // Adaptive cola options scaled to graph size so large graphs stay responsive:
  // past ~1500 nodes the simulation stops animating per-frame (one settle pass),
  // and iteration time shrinks as the graph grows.
  private colaOpts() {
    const n = this.cy.nodes().length;
    // animate:true ALWAYS. animate:false makes cola compute every iteration
    // synchronously, which BLOCKS the main thread and freezes the UI on big
    // graphs. Async animation spreads the work across frames so it never freezes.
    // fit:false ALWAYS — cola's own fit re-centers on the bounding box, which
    // fights our root-centering. We frame the viewport ourselves (frameContent).
    const maxSim = n > 1500 ? 700 : n > 600 ? 1500 : 2500;
    // Give cola a generous square area to lay out in, scaled to node count.
    // Without this, cytoscape defaults the layout boundingBox to the viewport, so
    // a short/small window crams every node into a tiny cluster. We frame it into
    // the real viewport ourselves afterwards (frameContent).
    const span = Math.max(1400, Math.round(Math.sqrt(n) * 320));
    return {
      name: "cola",
      animate: true,
      infinite: false,
      fit: false,
      boundingBox: { x1: 0, y1: 0, w: span, h: span },
      randomize: false,
      avoidOverlap: n < 500, // avoidOverlap is O(n²)-ish; only worth it when small
      handleDisconnected: true,
      nodeSpacing: () => 14,
      edgeLength: (edge: any) => (SHORT_EDGES.has(edge.data("label")) ? 70 : 190),
      maxSimulationTime: maxSim,
      convergenceThreshold: 0.05,
    } as any;
  }

  private lastRelax = 0;
  private dirty = false; // true when new nodes were added since the last relax
  private interactUntil = 0; // suppress relax until this time (user is interacting)
  /**
   * THROTTLED (not debounced) and size-adaptive. Runs the live cola simulation at
   * a steady cadence while deltas stream in, but ONLY when something actually
   * changed (dirty), and spaces runs further apart as the graph grows — so a
   * large graph never pins the CPU and the simulation goes idle once settled.
   */
  private scheduleRelax() {
    if (this.relaxTimer) return; // a run is already queued
    const n = this.cy.nodes().length;
    // Without the worker (fallback), a live cola re-layout of a huge graph is
    // too costly on the UI thread: placeNode stands in until finalize().
    if (n > 2500 && this.getWorker() === null) {
      this.dirty = false;
      return;
    }
    const interval = Math.min(3500, 600 + Math.floor(n / 150) * 300);
    const now = Date.now();
    // Respect both the throttle interval and any active-interaction hold.
    const due = Math.max(0, interval - (now - this.lastRelax), this.interactUntil - now);
    this.relaxTimer = window.setTimeout(() => {
      this.relaxTimer = null;
      this.lastRelax = Date.now();
      if (this.dirty) this.relax(false);
    }, due);
  }

  private followTimer: number | null = null;
  private layoutActive = false;
  private stopFollowing() {
    if (this.followTimer) {
      window.clearInterval(this.followTimer);
      this.followTimer = null;
    }
  }

  // ---------------------------------------------------------------------
  // Layout in a Web Worker (layoutCore.ts): fCoSE + leaf rings + overlap
  // removal. Nodes and their labels end up side by side instead of piled up,
  // and the heavy computation never blocks the UI. One run at a time; changes
  // that arrive meanwhile are coalesced into a single follow-up run.
  private worker: Worker | null | undefined; // undefined = not created yet
  private workerBusy = false;
  private workerQueued: { reframe: boolean; randomize: boolean } | null = null;
  private workerGen = 0; // bumped on reset(): results for an old graph are dropped
  private reqSeq = 0;
  private pendingReq: { id: number; gen: number; reframe: boolean } | null = null;
  private moved = new Set<string>(); // nodes the user dragged since the request
  /** Called with true while a layout is being computed (footer hint). */
  onLayoutBusy: ((busy: boolean) => void) | null = null;

  private getWorker(): Worker | null {
    if (this.worker !== undefined) return this.worker;
    try {
      const w = new Worker(new URL("./layout.worker.ts", import.meta.url), { type: "module" });
      w.onmessage = (e) => this.onWorkerResult(e.data);
      w.onerror = (e) => {
        console.warn("layout worker failed — falling back to the in-page layout", e);
        w.terminate();
        this.worker = null;
        this.workerBusy = false;
        this.workerQueued = null;
        this.onLayoutBusy?.(false);
        this.relaxCola(true);
      };
      this.worker = w;
    } catch (err) {
      console.warn("layout worker unavailable", err);
      this.worker = null;
    }
    return this.worker;
  }

  private relax(reframe: boolean, randomize = false) {
    if (this.cy.nodes().length === 0) return;
    this.dirty = false;
    // A full re-layout supersedes whatever is being computed: on a big graph
    // waiting for a now-useless incremental run would double the time.
    if (randomize && this.workerBusy && this.worker) {
      this.worker.terminate();
      this.worker = undefined;
      this.workerBusy = false;
      this.workerQueued = null;
      this.pendingReq = null;
    }
    const w = this.getWorker();
    if (!w) return this.relaxCola(reframe);
    if (this.workerBusy) {
      const q = this.workerQueued;
      this.workerQueued = { reframe: reframe || !!q?.reframe, randomize: randomize || !!q?.randomize };
      return;
    }
    this.workerBusy = true;
    this.onLayoutBusy?.(true);
    this.moved.clear();
    const nodes = this.cy.nodes().map((nd: any) => {
      const size = nd.data("size") as number;
      const b = nodeBox(size, nd.data("label") as string);
      const p = nd.position();
      return { id: nd.id(), size, w: b.w, h: b.h, x: p.x, y: p.y };
    });
    const edges = this.cy.edges().map((e: any) => ({ s: e.source().id(), t: e.target().id(), short: SHORT_EDGES.has(e.data("label")) }));
    this.pendingReq = { id: ++this.reqSeq, gen: this.workerGen, reframe };
    w.postMessage({ id: this.pendingReq.id, req: { nodes, edges, randomize } });
  }

  private onWorkerResult(msg: { id: number; pos?: Record<string, { x: number; y: number }>; error?: string }) {
    const meta = this.pendingReq;
    this.workerBusy = false;
    this.pendingReq = null;
    if (msg.error) console.warn("layout failed:", msg.error);
    else if (msg.pos && meta && msg.id === meta.id && meta.gen === this.workerGen) this.applyPositions(msg.pos, meta.reframe);
    const q = this.workerQueued;
    this.workerQueued = null;
    if (q) this.relax(q.reframe, q.randomize);
    else if (this.dirty) this.scheduleRelax();
    if (!this.workerBusy) this.onLayoutBusy?.(false);
  }

  /** Move nodes to computed positions (animated for graphs a browser can animate smoothly). */
  private applyPositions(pos: Record<string, { x: number; y: number }>, reframe: boolean) {
    if (this.layout) this.layout.stop();
    const n = this.cy.nodes().length;
    const fresh: NodeSingular[] = []; // added after the request was sent
    this.layout = this.cy.nodes().layout({
      name: "preset",
      positions: (nd: any) => {
        if (this.moved.has(nd.id())) return nd.position(); // keep the user's drag
        const p = pos[nd.id()];
        if (!p) fresh.push(nd);
        return p ?? nd.position();
      },
      animate: n <= 1500,
      animationDuration: 450,
      fit: false,
    } as any);
    this.layoutActive = true;
    this.layout.one("layoutstop", () => {
      this.layoutActive = false;
      // Nodes that arrived during the computation: seed them next to their
      // (now moved) neighbour; the next run places them properly.
      for (const nd of fresh) {
        nd.scratch("_placed", false);
        this.placeNode(nd);
      }
      if (fresh.length) this.dirty = true;
      if (reframe && Date.now() >= this.interactUntil) this.frameContent();
    });
    this.layout.run();
  }

  // reframe=true: keep the viewport on the nodes while cola settles, then frame
  // once more at the end. cola moves every node into its own bounding box on
  // the very first tick, so a single frame taken before the run pointed at the
  // old, now-empty positions — after a diff / opening a stored scan the graph
  // looked completely blank for the ~2.5 s the layout took.
  // Fallback when Web Workers are unavailable.
  private relaxCola(reframe: boolean) {
    if (this.cy.nodes().length === 0) return;
    this.dirty = false;
    this.stopFollowing();
    if (this.layout) this.layout.stop();
    this.layout = this.cy.layout(this.colaOpts());
    this.layoutActive = true;
    this.layout.one("layoutstop", () => (this.layoutActive = false));
    if (reframe) {
      this.followTimer = window.setInterval(() => {
        if (Date.now() >= this.interactUntil) this.frameContent();
      }, 200);
      this.layout.one("layoutstop", () => {
        this.stopFollowing();
        if (Date.now() >= this.interactUntil) this.frameContent();
      });
    }
    this.layout.run();
  }

  /** Public: lay the whole graph out again from scratch (↻ button). */
  relayout() {
    this.relax(true, true);
  }

  /** Called when a scan finishes: final settle + fit. */
  finalize() {
    if (this.relaxTimer) {
      window.clearTimeout(this.relaxTimer);
      this.relaxTimer = null;
    }
    this.frameContent(); // immediate centered view
    // A finished scan gets a global layout from scratch (spectral start): the
    // incremental live layout keeps positions stable but cannot untangle
    // everything that was added piece by piece.
    this.relax(true, true);
  }

  /**
   * Make the view equal to a full server snapshot: drop every element the
   * snapshot no longer has (a scan started elsewhere, the server restarted,
   * another tab opened a stored scan), then add/update the rest. Positions of
   * surviving nodes are kept, so a reconnect mid-scan doesn't reshuffle.
   */
  sync(snap: graph.Delta) {
    const nodeIds = new Set((snap.nodes ?? []).map((n) => n?.id).filter(Boolean));
    const edgeIds = new Set((snap.edges ?? []).map((e) => e?.id).filter(Boolean));
    const stale = this.cy.elements().filter((el: any) => (el.isNode() ? !nodeIds.has(el.id()) : !edgeIds.has(el.id())));
    if (stale.length > 0) {
      this.cy.batch(() => stale.remove());
      for (const id of [...this.orphanEdges.keys()]) if (!edgeIds.has(id)) this.orphanEdges.delete(id);
    }
    this.apply(snap);
  }

  reset(delta?: graph.Delta) {
    if (this.relaxTimer) {
      window.clearTimeout(this.relaxTimer);
      this.relaxTimer = null;
    }
    this.lastRelax = 0;
    this.dirty = false;
    this.lastFit = 0;
    this.stopFollowing();
    this.workerGen++; // an in-flight result belongs to the old graph
    this.workerQueued = null;
    if (this.layout) this.layout.stop();
    this.orphanEdges.clear();
    this.cy.elements().remove();
    // Reset the viewport to a known centered state so the first node of the next
    // scan appears dead-center rather than off-screen.
    this.cy.resize();
    this.cy.zoom(1);
    this.cy.center();
    if (delta) {
      this.apply(delta);
      this.frameContent();
    }
  }

  destroy() {
    if (this.ro) this.ro.disconnect();
    this.worker?.terminate();
    this.stopFollowing();
    if (this.relaxTimer) window.clearTimeout(this.relaxTimer);
    if (this.layout) this.layout.stop();
    this.cy.destroy();
  }
}
