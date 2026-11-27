// Russian names for identifiers that come from the server (scan stages, node
// types, severities). The server keeps stable English keys; the UI shows these.

const STAGES: Record<string, string> = {
  Discovery: "Обнаружение",
  Resolve: "Разрешение имён",
  Probe: "Зондирование",
  Web: "Веб-порты",
  Enrich: "Обогащение",
  Post: "Анализ",
  Done: "Готово",
};

/** Display name of a scan stage ("Discovery" → "Обнаружение"). */
export function stageName(stage: string | undefined | null): string {
  if (!stage) return "";
  return STAGES[stage] ?? stage;
}

const TYPES: Record<string, string> = {
  ip: "IP",
  domain: "домен",
  subdomain: "поддомен",
  port: "порт",
  service: "сервис",
  technology: "технология",
  certificate: "сертификат",
  asn: "ASN",
  whois_org: "организация",
  url: "URL",
  email: "email",
  cve: "CVE",
  finding: "находка",
  param: "параметр",
  bucket: "бакет",
};

/** Display name of a node type ("subdomain" → "поддомен"). */
export function typeName(t: string | undefined | null): string {
  if (!t) return "";
  return TYPES[t] ?? t;
}

const SEVERITIES: Record<string, string> = {
  critical: "критическая",
  high: "высокая",
  medium: "средняя",
  low: "низкая",
  info: "инфо",
  none: "нет",
  unknown: "неизвестна",
};

/** Display name of a severity ("HIGH" → "высокая"). */
export function severityName(s: unknown): string {
  const k = String(s ?? "").toLowerCase();
  return SEVERITIES[k] ?? String(s ?? "");
}
