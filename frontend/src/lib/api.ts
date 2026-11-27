// Browser client for the osint-forge Go web server. It keeps the same function
// names the Wails bindings had, so App.svelte barely changed.
import type { config, core, graph, history, scan } from "./models";

/** An API error carrying the HTTP status (e.g. 409 = needs an explicit click). */
export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function req<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) throw new ApiError((data && data.error) || text || res.statusText, res.status);
  return data as T;
}

const q = (v: string) => encodeURIComponent(v);

export const ParseTarget = (raw: string) => req<core.Target>("GET", `/api/parse?target=${q(raw)}`);
export const StartScan = (target: string, consent: boolean) =>
  req<void>("POST", "/api/scan", { target, consent });
export const CancelScan = () => req<void>("POST", "/api/cancel", {});
export const Snapshot = () => req<graph.Delta>("GET", "/api/snapshot");
export const Status = () => req<{ running: boolean; target: string }>("GET", "/api/status");
export const DiffPrevious = (target: string) => req<history.Diff>("GET", `/api/diff?target=${q(target)}`);
export const GetConfig = () => req<config.Config>("GET", "/api/config");
export const SaveConfig = (cfg: config.Config) => req<void>("PUT", "/api/config", cfg);
export const NmapInstalled = () => req<boolean>("GET", "/api/nmap");
export const FetchPage = (url: string) => req<scan.Page>("GET", `/api/page?url=${q(url)}`);
/** URL of a stored screenshot; `version` busts the browser cache after a re-capture. */
export const screenshotURL = (path: string, version = "") =>
  `/api/screenshot?path=${q(path)}${version ? `&v=${q(version)}` : ""}`;

export interface Shot { url: string; path: string; takenAt: string; cached: boolean }
/**
 * Screenshot of one URL node, taken on demand when none is stored.
 * auto=true: opened automatically with the panel — the server refuses (409)
 * for pages the scan never requested or when screenshots are switched off.
 */
export const CaptureScreenshot = (url: string, opts: { force?: boolean; auto?: boolean } = {}, signal?: AbortSignal) =>
  req<Shot>("POST", "/api/screenshot", { url, force: !!opts.force, auto: !!opts.auto }, signal);

// Links open in a new tab (only http/https — never javascript: etc.).
export function OpenURL(url: string) {
  try {
    const u = new URL(url);
    if (u.protocol === "http:" || u.protocol === "https:") window.open(u.href, "_blank", "noopener,noreferrer");
  } catch {
    /* ignore invalid URLs */
  }
}

// Exports are plain browser downloads.
export type ExportFormat = "json" | "html" | "md" | "csv" | "sarif" | "obsidian";
export async function Export(format: ExportFormat, target = ""): Promise<string> {
  const res = await fetch(`/api/export/${format}?target=${q(target)}`);
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = (await res.json()).error || msg;
    } catch {}
    throw new Error(msg);
  }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const name = /filename="([^"]+)"/.exec(cd)?.[1] || `osint-forge.${format}`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
  return `${name} yuklab olindi`;
}

// --- Server-Sent Events (replaces Wails EventsOn) ---

type Handler = (data: any) => void;
const handlers = new Map<string, Set<Handler>>();
let es: EventSource | null = null;
let reconnectHandlers = new Set<() => void>();
let opened = false;

function ensureStream() {
  if (es) return;
  es = new EventSource("/api/events");
  es.onopen = () => {
    // After a reconnect, events may have been missed: let the UI resync.
    if (opened) reconnectHandlers.forEach((f) => f());
    opened = true;
  };
  for (const name of handlers.keys()) attach(name);
}

function attach(name: string) {
  es?.addEventListener(name, (ev) => {
    const data = JSON.parse((ev as MessageEvent).data);
    handlers.get(name)?.forEach((h) => h(data));
  });
}

export function EventsOn(name: string, h: Handler): () => void {
  if (!handlers.has(name)) {
    handlers.set(name, new Set());
    if (es) attach(name);
  }
  handlers.get(name)!.add(h);
  ensureStream();
  return () => handlers.get(name)?.delete(h);
}

export function OnReconnect(f: () => void): () => void {
  reconnectHandlers.add(f);
  return () => reconnectHandlers.delete(f);
}

// --- scan history ---
export interface HistoryTarget { target: string; scans: number; last: string }
export interface HistoryEntry { id: string; target: string; when: string; nodes: number; edges: number; findings: number }
export interface Compare { target: string; from: string; to: string; graph: graph.Delta; added: string[] | null; removed: string[] | null }
export const HistoryTargets = () => req<HistoryTarget[]>("GET", "/api/history");
export const HistoryList = (target: string) => req<HistoryEntry[]>("GET", `/api/history/${q(target)}`);
export const HistoryOpen = (target: string, id: string) =>
  req<graph.Delta>("POST", `/api/history/${q(target)}/${q(id)}/open`, {});
export const HistoryDelete = (target: string, id: string) => req<void>("DELETE", `/api/history/${q(target)}/${q(id)}`);
export const HistoryCompare = (target: string, from = "", to = "") =>
  req<Compare>("GET", `/api/history/${q(target)}/compare?from=${q(from)}&to=${q(to)}`);

// --- per-source timings ---
export interface SourceTiming {
  name: string; stage: string; status: string; startedAt: number; durationMs: number;
  nodes: number; edges: number; error?: string;
}
export const Timings = () => req<SourceTiming[]>("GET", "/api/timings");

// --- pentester notes / tags ---
export interface Note { tags?: string[]; text?: string; updated?: string }
export const TAGS: { key: string; label: string; icon: string }[] = [
  { key: "vuln", label: "Zaif", icon: "🐞" },
  { key: "checked", label: "Tekshirildi", icon: "✔" },
  { key: "interesting", label: "Qiziq", icon: "⭐" },
  { key: "fp", label: "False positive", icon: "✖" },
];
export const NotesLoad = (target: string) => req<Record<string, Note>>("GET", `/api/notes?target=${q(target)}`);
export const NoteSave = (target: string, node: string, tags: string[], text: string) =>
  req<Note>("PUT", "/api/notes", { target, node, tags, text });

// --- continuous monitoring ---
/** Which changes of a watched target trigger an alert (empty = everything). */
export interface AlertFilter { types?: string[]; minSeverity?: string; ignoreRemoved?: boolean; preset?: string }
export interface Watch { target: string; intervalMin: number; consent: boolean; added: string; lastRun: string; nextRun: string; lastChange?: string; filter?: AlertFilter }
export const MonitorList = () => req<Watch[]>("GET", "/api/monitor");
export const MonitorAdd = (target: string, intervalMin: number, consent: boolean, filter: AlertFilter) =>
  req<Watch>("POST", "/api/monitor", { target, intervalMin, consent, filter });
export const MonitorRemove = (target: string) => req<void>("DELETE", `/api/monitor/${q(target)}`);
export const NotifyTest = () => req<void>("POST", "/api/notify/test", {});
