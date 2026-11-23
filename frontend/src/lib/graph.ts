// Cytoscape wrapper. Renders an Obsidian-like graph with a LIVE, continuously
// animating force simulation (cola.js). Unlike a batch layout (fcose), cola runs
// asynchronously a little per animation frame, so nodes glide into place while a
// scan streams in and the UI never freezes.
import cytoscape, { type Core, type ElementDefinition, type NodeSingular } from "cytoscape";
// @ts-ignore - cytoscape-cola ships no types
import cola from "cytoscape-cola";
import type { graph } from "../../wailsjs/go/models";

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

function colorFor(n: graph.Node): string {
  if (n.type === "cve" || n.type === "finding") {
    const col = severityColor(String(n.props?.severity ?? ""));
    if (col) return col;
  }
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
            // haystack = a plain straight segment between node centres; unlike
            // bezier/straight it never degenerates into a thick bar when two
            // connected nodes sit very close.
            "curve-style": "haystack",
            "haystack-radius": 0,
            // The real remaining artifact is the HUB: the root/domain has dozens of
            // edges all converging on its centre, which opaque merge into a solid
            // gray wedge. Low opacity makes that convergence read as a soft fan and
            // keeps individual edges legible (the Obsidian look).
            opacity: 0.4,
            "overlay-opacity": 0,
          },
        },
        { selector: "edge.focus", style: { "line-color": "#93c5fd", opacity: 1, width: 2 } },
        { selector: ".dim", style: { opacity: 0.07 } },
      ],
      elements: [],
    });

    // Cytoscape has no built-in double-tap event, so detect it manually: a second
    // tap on the same node within 320ms is a double-click (opens the panel); a
    // single tap just highlights the node's connections.
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

  /** Live element counts, for the footer. */
  counts(): { nodes: number; edges: number } {
    return { nodes: this.cy.nodes().length, edges: this.cy.edges().length };
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
        root: n.props?.root ? 1 : 0, // the scan target — kept centered
        raw: n,
      },
    };
  }

  /** Add a delta's new elements and nudge the live simulation. */
  apply(delta: graph.Delta) {
    const newIds: string[] = [];
    const batch: ElementDefinition[] = [];
    for (const n of delta.nodes ?? []) {
      const ex = this.cy.getElementById(n.id);
      if (ex.empty()) {
        batch.push(this.toElement(n));
        newIds.push(n.id);
      } else {
        ex.data("raw", n);
        ex.data("color", colorFor(n));
        ex.data("kev", n.props?.known_exploited ? 1 : 0);
      }
    }
    for (const e of delta.edges ?? []) {
      if (this.cy.getElementById(e.id).empty()) {
        batch.push({ group: "edges", data: { id: e.id, source: e.source, target: e.target, label: e.label } });
      }
    }
    if (batch.length === 0) return;

    this.cy.add(batch);
    // IMPORTANT: place nodes AFTER cy.add has fully applied (not inside cy.batch).
    // Inside a batch, cytoscape defers index updates, so node.neighborhood() would
    // return empty and every node would collapse onto the origin — leaving the whole
    // graph piled at one point with only the root visible.
    for (const id of newIds) this.placeNode(this.cy.getElementById(id) as NodeSingular);
    if (newIds.length > 0) this.dirty = true;
    this.scheduleRelax();
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
    // Above this size a live re-layout every few seconds is too costly; the cheap
    // radial placeNode positions stand in during the scan, and a single settling
    // pass runs at the end (finalize).
    if (n > 2500) {
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

  // reframe=true: once cola settles, re-frame the viewport centered on the root.
  private relax(reframe: boolean) {
    if (this.cy.nodes().length === 0) return;
    this.dirty = false;
    if (this.layout) this.layout.stop();
    this.layout = this.cy.layout(this.colaOpts());
    if (reframe) {
      this.layout.one("layoutstop", () => {
        if (Date.now() >= this.interactUntil) this.frameContent();
      });
    }
    this.layout.run();
  }

  /** Public: run a settling pass (↻ button / scan end). */
  relayout() {
    this.relax(true);
  }

  /** Called when a scan finishes: final settle + fit. */
  finalize() {
    if (this.relaxTimer) {
      window.clearTimeout(this.relaxTimer);
      this.relaxTimer = null;
    }
    this.frameContent(); // immediate centered view
    this.relax(true); // cola refines and fits
  }

  reset(delta?: graph.Delta) {
    if (this.relaxTimer) {
      window.clearTimeout(this.relaxTimer);
      this.relaxTimer = null;
    }
    this.lastRelax = 0;
    this.dirty = false;
    this.lastFit = 0;
    if (this.layout) this.layout.stop();
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
    if (this.relaxTimer) window.clearTimeout(this.relaxTimer);
    if (this.layout) this.layout.stop();
    this.cy.destroy();
  }
}
