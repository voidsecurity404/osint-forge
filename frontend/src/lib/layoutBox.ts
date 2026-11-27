// Size of a node's footprint: its circle plus the label hanging below it.
// Shared by the UI (graph.ts) and the layout worker (layoutCore.ts).

/** Label below the circle: font 10px, text-max-width 140px, 3px margin. */
export function nodeBox(size: number, label: string): { w: number; h: number } {
  const text = Math.min(144, Math.ceil((label?.length ?? 0) * 6.2) + 4);
  return { w: Math.max(size, text), h: size + 17 };
}
