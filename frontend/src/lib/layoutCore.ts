// Graph layout core — pure computation, no DOM. Runs inside a Web Worker (see
// layout.worker.ts) so even a multi-thousand-node graph is laid out without
// freezing the UI, and can be benchmarked from Node.
//
// Two steps:
//  1. fCoSE (spectral initialisation + compound spring embedder) — finds the
//     global structure: hosts with their ports/services/CVEs form clusters
//     instead of one dense ball.
//  2. removeOverlaps — a grid-accelerated push-apart pass over the node
//     RECTANGLES INCLUDING THEIR LABELS, so circles and their text never sit
//     on top of each other.
import cytoscape from "cytoscape";
// @ts-ignore - cytoscape-fcose ships no types
import fcose from "cytoscape-fcose";

cytoscape.use(fcose);

/** A node to place. w/h cover the circle AND its label (label below the node). */
export interface LNode {
  id: string;
  size: number; // circle diameter
  w: number; // width of circle ∪ label
  h: number; // height of circle + label
  x?: number;
  y?: number;
}
export interface LEdge {
  s: string;
  t: string;
  short?: boolean; // tight parent→child relation (port→service, service→cve…)
}
export interface LRequest {
  nodes: LNode[];
  edges: LEdge[];
  /** true: global re-layout from scratch; false: refine current positions. */
  randomize: boolean;
}
export type Positions = Record<string, { x: number; y: number }>;

export { nodeBox } from "./layoutBox";

/** Optional knobs (benchmarks); defaults are tuned per graph size. */
export interface LTune {
  quality?: "draft" | "default" | "proof";
  numIter?: number;
  spread?: number;
  hubFactor?: number;
  overlapMs?: number;
}

export function computeLayout(req: LRequest, tune: LTune = {}): Positions {
  const n = req.nodes.length;
  if (n === 0) return {};
  const byId = new Map(req.nodes.map((x) => [x.id, x]));
  const edges = req.edges.filter((e) => e.s !== e.t && byId.has(e.s) && byId.has(e.t));

  // ---- 1. Leaves (CVEs, fuzzed paths, params, unresolved names…) ----------
  // A leaf has exactly one neighbour. Most recon nodes are leaves hanging off
  // a few hubs, and force layouts pile them up. They are laid out in rings
  // around their parent instead; the parent reserves the room in step 2.
  const nbrs = new Map<string, Set<string>>();
  for (const e of edges) {
    (nbrs.get(e.s) ?? nbrs.set(e.s, new Set()).get(e.s)!).add(e.t);
    (nbrs.get(e.t) ?? nbrs.set(e.t, new Set()).get(e.t)!).add(e.s);
  }
  const leavesOf = new Map<string, LNode[]>();
  const isLeaf = new Set<string>();
  for (const x of req.nodes) {
    const nb = nbrs.get(x.id);
    if (!nb || nb.size !== 1) continue;
    const parent = [...nb][0];
    if ((nbrs.get(parent)?.size ?? 0) < 2) continue; // a 2-node island stays as is
    isLeaf.add(x.id);
    (leavesOf.get(parent) ?? leavesOf.set(parent, []).get(parent)!).push(x);
  }
  const rings = new Map<string, Ring>();
  for (const [parent, leaves] of leavesOf) rings.set(parent, ringLayout(byId.get(parent)!, leaves));

  // ---- 2. Core graph with fCoSE -----------------------------------------
  const core = req.nodes.filter((x) => !isLeaf.has(x.id));
  const coreIds = new Set(core.map((x) => x.id));
  const coreEdges = edges.filter((e) => coreIds.has(e.s) && coreIds.has(e.t));
  const deg = new Map<string, number>();
  for (const e of coreEdges) {
    deg.set(e.s, (deg.get(e.s) ?? 0) + 1);
    deg.set(e.t, (deg.get(e.t) ?? 0) + 1);
  }
  // Box of a core node as fCoSE sees it: its own box, or its leaf ring disc.
  const coreBox = (x: LNode) => {
    const r = rings.get(x.id);
    const d = r ? 2 * r.radius : 0;
    return { w: Math.max(x.w, d), h: Math.max(x.h, d) };
  };
  let boxArea = 0;
  for (const x of core) boxArea += (x.w + 10) * (x.h + 10);
  const avgArea = boxArea / Math.max(1, core.length);
  // Degree-aware edge lengths: a core hub's children need room on its ring.
  const edgeLen = (short: boolean, s: string, t: string) => {
    const hub = Math.max(deg.get(s) ?? 1, deg.get(t) ?? 1);
    return Math.max(short ? 60 : 150, (tune.hubFactor ?? 1.0) * Math.sqrt((hub * avgArea) / Math.PI));
  };
  const corePos = new Map<string, { x: number; y: number }>();
  if (core.length === 1) corePos.set(core[0].id, { x: core[0].x ?? 0, y: core[0].y ?? 0 });
  else if (core.length > 1) {
    const elements: any[] = core.map((x) => {
      const b = coreBox(x);
      return { group: "nodes", data: { id: x.id, w: b.w, h: b.h }, position: { x: x.x ?? 0, y: x.y ?? 0 } };
    });
    coreEdges.forEach((e, i) =>
      elements.push({ group: "edges", data: { id: "e" + i, source: e.s, target: e.t, len: edgeLen(!!e.short, e.s, e.t), short: e.short ? 1 : 0 } }),
    );
    const cy = cytoscape({
      headless: true,
      styleEnabled: true,
      elements,
      style: [{ selector: "node", style: { width: "data(w)", height: "data(h)", shape: "rectangle" } } as any],
    });
    // Without randomize, fCoSE skips the spectral phase and refines the
    // current positions (live updates keep the user's mental map).
    cy.layout({
      name: "fcose",
      // "proof" polishes small graphs; big ones get "default" (≈ half the time)
      quality: tune.quality ?? (core.length > 500 ? "default" : "proof"),
      randomize: req.randomize,
      animate: false,
      fit: false,
      nodeDimensionsIncludeLabels: false, // labels are already inside w/h
      uniformNodeDimensions: false,
      packComponents: true,
      tile: true,
      tilingPaddingVertical: 30,
      tilingPaddingHorizontal: 30,
      nodeRepulsion: () => 9000,
      idealEdgeLength: (e: any) => e.data("len"),
      edgeElasticity: (e: any) => (e.data("short") ? 0.6 : 0.4),
      nodeSeparation: 90,
      gravity: 0.18,
      gravityRange: 3.8,
      numIter: tune.numIter ?? 2500,
      initialEnergyOnIncremental: 0.3,
    } as any).run();
    cy.nodes().forEach((nd: any) => {
      corePos.set(nd.id(), { ...nd.position() });
    });
    cy.destroy();
  }

  // ---- 3. Separate the core "discs" (a node plus its leaf rings) ---------
  // fCoSE treats node sizes softly; leaf rings of neighbouring hubs would
  // interlock. Few, big objects converge fast, and once discs are disjoint the
  // leaves of different parents can never collide.
  if (core.length > 1) {
    const discs = core.map((x) => {
      const b = coreBox(x);
      const p = corePos.get(x.id)!;
      return { id: x.id, x: p.x, y: p.y, w: b.w, h: b.h, size: b.h }; // size=h ⇒ box centred
    });
    removeOverlaps(discs, 10, 100000, 1000 + core.length * 1.5);
    for (const d of discs) corePos.set(d.id, { x: d.x, y: d.y });
  }

  // ---- 4. Leaves around their parent; 5. resolve what still collides ------
  const items = req.nodes.map((x) => ({ id: x.id, size: x.size, w: x.w, h: x.h, x: 0, y: 0 }));
  const itemById = new Map(items.map((it) => [it.id, it]));
  for (const x of core) Object.assign(itemById.get(x.id)!, corePos.get(x.id));
  for (const [parent, ring] of rings) {
    const p = itemById.get(parent)!;
    for (const [id, off] of ring.offsets) Object.assign(itemById.get(id)!, { x: p.x + off.x, y: p.y + off.y });
  }
  spreadOut(items, tune.spread ?? 1.2);
  // Time budget grows with the graph: ~1.5 s small, ~7 s at 4k nodes.
  removeOverlaps(items, 6, 100000, tune.overlapMs ?? 1500 + n * 1.5);
  const out: Positions = {};
  for (const it of items) out[it.id] = { x: it.x, y: it.y };
  return out;
}

interface Ring {
  radius: number; // outer radius of the leaf rings (room the parent reserves)
  offsets: Map<string, { x: number; y: number }>;
}

/**
 * Concentric rings of leaves around their parent. Each leaf takes an arc as
 * long as its box is wide (+ padding), so neighbours on a ring never touch;
 * a full ring starts the next, larger one.
 */
export function ringLayout(parent: LNode, leaves: LNode[]): Ring {
  const pad = 10;
  const gap = Math.max(...leaves.map((l) => l.h)) + pad;
  let r = Math.max(parent.w, parent.h) / 2 + gap * 0.9;
  const offsets = new Map<string, { x: number; y: number }>();
  const sorted = [...leaves].sort((a, b) => a.id.localeCompare(b.id));
  let i = 0;
  let outer = r;
  while (i < sorted.length) {
    const circ = 2 * Math.PI * r;
    // how many of the remaining leaves fit on this ring
    let used = 0;
    let j = i;
    while (j < sorted.length && used + sorted[j].w + pad <= circ) {
      used += sorted[j].w + pad;
      j++;
    }
    if (j === i) j = i + 1; // a box wider than the whole ring: place it anyway
    const slice = sorted.slice(i, j);
    // spread the slice evenly over the full circle
    const total = slice.reduce((a, l) => a + l.w + pad, 0);
    let arc = 0;
    for (const l of slice) {
      const mid = arc + (l.w + pad) / 2;
      const ang = (mid / total) * 2 * Math.PI - Math.PI / 2;
      // labels hang below the circle: shift so the box (not the circle) is centred
      offsets.set(l.id, { x: r * Math.cos(ang), y: r * Math.sin(ang) - (l.h - l.size) / 2 });
      arc += l.w + pad;
    }
    outer = r + Math.max(...slice.map((l) => l.w)) / 2;
    i = j;
    r += gap;
  }
  return { radius: outer + pad, offsets };
}

/**
 * Scale positions about their centre until the layout's area is at least
 * `ratio` × the total area the node rectangles need. Force layouts squeeze big
 * graphs into a ball far smaller than the boxes require; scaling keeps the
 * structure (clusters stay clusters) and leaves the overlap pass only local
 * fixes instead of an endless cascade of pushes.
 */
export function spreadOut(items: { x: number; y: number; w: number; h: number }[], ratio: number) {
  if (items.length < 2) return;
  let need = 0, x1 = Infinity, y1 = Infinity, x2 = -Infinity, y2 = -Infinity;
  for (const it of items) {
    need += (it.w + 8) * (it.h + 8);
    x1 = Math.min(x1, it.x); x2 = Math.max(x2, it.x);
    y1 = Math.min(y1, it.y); y2 = Math.max(y2, it.y);
  }
  const area = Math.max(1, (x2 - x1) * (y2 - y1));
  const k = Math.sqrt((need * ratio) / area);
  if (k <= 1) return;
  const cx = (x1 + x2) / 2, cy = (y1 + y2) / 2;
  for (const it of items) {
    it.x = cx + (it.x - cx) * k;
    it.y = cy + (it.y - cy) * k;
  }
}

/**
 * Push apart every pair of overlapping rectangles (circle + label). Each node's
 * rectangle spans [x - w/2, x + w/2] × [y - size/2, y - size/2 + h] because the
 * label hangs below the circle. Separation happens along the axis of least
 * penetration, so nodes move as little as possible. A uniform grid keeps each
 * pass O(n); a few dozen passes leave virtually no overlap.
 */
export function removeOverlaps(
  items: { x: number; y: number; w: number; h: number; size: number }[],
  pad = 6,
  maxPasses = 80,
  budgetMs = Infinity,
): number {
  const started = Date.now();
  const n = items.length;
  if (n < 2) return 0;
  let cell = 0;
  for (const it of items) cell = Math.max(cell, it.w + pad, it.h + pad);
  let remaining = 0;
  for (let pass = 0; pass < maxPasses; pass++) {
    const grid = new Map<string, number[]>();
    const top = (it: (typeof items)[0]) => it.y - it.size / 2;
    items.forEach((it, i) => {
      const k = Math.floor(it.x / cell) + "," + Math.floor(top(it) / cell);
      const l = grid.get(k);
      if (l) l.push(i);
      else grid.set(k, [i]);
    });
    remaining = 0;
    for (const [key, list] of grid) {
      const [gx, gy] = key.split(",").map(Number);
      // compare against this cell and the 4 "forward" neighbours (each pair once)
      for (const [dx, dy] of [[0, 0], [1, 0], [-1, 1], [0, 1], [1, 1]]) {
        const other = dx === 0 && dy === 0 ? list : grid.get(gx + dx + "," + (gy + dy));
        if (!other) continue;
        for (let a = 0; a < list.length; a++) {
          for (let b = dx === 0 && dy === 0 ? a + 1 : 0; b < other.length; b++) {
            const p = items[list[a]], q = items[other[b]];
            const ox = (p.w + q.w) / 2 + pad - Math.abs(p.x - q.x);
            const pc = top(p) + p.h / 2, qc = top(q) + q.h / 2;
            const oy = (p.h + q.h) / 2 + pad - Math.abs(pc - qc);
            if (ox <= 0 || oy <= 0) continue;
            remaining++;
            // Push along the line between the centres (not along one axis):
            // axis-only pushes stack dense regions into rows and columns,
            // radial pushes let a crowded cluster expand naturally.
            let dx = p.x - q.x;
            let dy = pc - qc;
            if (Math.abs(dx) < 0.01 && Math.abs(dy) < 0.01) {
              const ang = ((list[a] * 7919 + other[b] * 104729) % 360) * (Math.PI / 180); // deterministic jitter
              dx = Math.cos(ang);
              dy = Math.sin(ang);
            }
            const len = Math.hypot(dx, dy);
            const ux = dx / len, uy = dy / len;
            // distance along u after which one axis no longer overlaps
            const t = Math.min(
              Math.abs(ux) > 1e-6 ? ox / Math.abs(ux) : Infinity,
              Math.abs(uy) > 1e-6 ? oy / Math.abs(uy) : Infinity,
            ) + 0.5;
            p.x += (ux * t) / 2;
            p.y += (uy * t) / 2;
            q.x -= (ux * t) / 2;
            q.y -= (uy * t) / 2;
          }
        }
      }
    }
    if (remaining === 0 || Date.now() - started > budgetMs) break;
  }
  return remaining;
}
