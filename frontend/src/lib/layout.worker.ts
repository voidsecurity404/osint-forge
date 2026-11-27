// Web Worker: runs the (CPU-heavy) graph layout off the UI thread, so even a
// multi-thousand-node graph never freezes the page while it is laid out.
import { computeLayout, type LRequest } from "./layoutCore";

self.onmessage = (e: MessageEvent<{ id: number; req: LRequest }>) => {
  const { id, req } = e.data;
  try {
    const t0 = performance.now();
    const pos = computeLayout(req);
    (self as any).postMessage({ id, pos, ms: Math.round(performance.now() - t0) });
  } catch (err) {
    (self as any).postMessage({ id, error: String((err as any)?.message ?? err) });
  }
};
