<script lang="ts">
  import { GetConfig, SaveConfig } from "../lib/api";
  import { app, errMsg } from "../lib/state.svelte";
  import type { config } from "../lib/models";

  let { open = $bindable(false) } = $props();
  let cfg = $state<(config.Config & Record<string, any>) | null>(null);
  // extra_scope is a list; edited as one entry per line.
  let scopeText = $state("");
  // fuzz_wordlist is a builtin name OR a path to the user's own file.
  const BUILTIN_LISTS = ["common", "raft-directories", "raft-files", "combo"];
  let listChoice = $state("common");
  let listPath = $state("");

  $effect(() => {
    if (open && !cfg) {
      GetConfig()
        .then((c) => {
          cfg = c as any;
          scopeText = (c.extra_scope ?? []).join("\n");
          const wl = (c.fuzz_wordlist ?? "").trim() || "common";
          listChoice = BUILTIN_LISTS.includes(wl) ? wl : "custom";
          listPath = BUILTIN_LISTS.includes(wl) ? "" : wl;
        })
        .catch((e) => app.flash("❌ " + errMsg(e)));
    }
    if (!open) cfg = null;
  });

  async function save() {
    if (!cfg) return;
    cfg.extra_scope = scopeText.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (listChoice === "custom") {
      if (!listPath.trim()) {
        app.flash("❌ Укажите путь к файлу своего словаря");
        return;
      }
      cfg.fuzz_wordlist = listPath.trim();
    } else {
      cfg.fuzz_wordlist = listChoice;
    }
    // Empty number inputs arrive as null; the server treats 0 as "default".
    for (const k of ["max_concurrent", "scan_timeout_min", "rate_limit_per_host"]) {
      if (typeof cfg[k] !== "number" || !Number.isFinite(cfg[k])) cfg[k] = 0;
    }
    try {
      await SaveConfig(cfg);
      app.flash("✅ Настройки сохранены");
      open = false;
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
</script>

{#if open && cfg}
  <div class="modal-bg" role="presentation" onclick={() => (open = false)}>
    <div class="modal" role="dialog" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.key === "Escape" && (open = false)}>
      <h2>Настройки</h2>
      <label>Ключ API SecurityTrails
        <input type="password" bind:value={cfg.securitytrails_key} /></label>
      <label>Ключ API VirusTotal
        <input type="password" bind:value={cfg.virustotal_key} /></label>
      <label>Ключ API NVD (необязательно)
        <input type="password" bind:value={cfg.nvd_key} /></label>
      <label>Аргументы nmap
        <input type="text" bind:value={cfg.nmap_args} placeholder="-sV -T4 --top-ports 1000" /></label>
      <label>HTTP User-Agent
        <input type="text" bind:value={cfg.http_user_agent} placeholder="osint-forge/0.1 (+recon)" /></label>
      <label>Показываемые коды статуса
        <input type="text" bind:value={cfg.status_codes} placeholder="2xx,3xx,401,403,5xx" />
        <span class="hint">Например: 200,301,403 или 2xx,3xx,5xx · пусто = все</span></label>
      <label>Параллельность (1–256)
        <input type="number" min="1" max="256" bind:value={cfg.max_concurrent} /></label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.fuzz_enabled} />
        Фаззинг путей (перебор путей на живых веб-хостах)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.subdomain_bruteforce} />
        Перебор поддоменов (DNS, 5000 имён)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.zone_transfer} />
        Проверка переноса зоны (AXFR)
      </label>
      <label>Словарь для фаззинга (SecLists)
        <select bind:value={listChoice}>
          <option value="common">common (~4,7 тыс., быстро)</option>
          <option value="raft-directories">raft-directories (~30 тыс.)</option>
          <option value="raft-files">raft-files (~17 тыс.)</option>
          <option value="combo">combo (папки + файлы)</option>
          <option value="custom">Свой файл…</option>
        </select>
      </label>
      {#if listChoice === "custom"}
        <label>Файл словаря (полный путь)
          <input type="text" bind:value={listPath} placeholder="/home/user/wordlists/my.txt" />
          <span class="hint">По одному пути в строке; строка с # — комментарий. Если файл не читается, используется «common».</span></label>
      {/if}

      <h3 class="settings-group">Безопасность / область</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.scope_strict} />
        Защита области — активное сканирование только домена/IP цели (рекомендуется)
      </label>
      <label>Дополнительная область (по одному домену или CIDR в строке)
        <textarea rows="3" bind:value={scopeText} placeholder={"partner.org\n10.0.0.0/8"}></textarea>
        <span class="hint">Добавляйте только домены/сети, на которые есть письменное разрешение, — они тоже будут сканироваться активно.</span></label>
      <label>Лимит времени сканирования (мин., 0 = без ограничения)
        <input type="number" bind:value={cfg.scan_timeout_min} /></label>
      <label>Ограничение скорости запросов (в сек. на хост, 0 = по умолчанию)
        <input type="number" bind:value={cfg.rate_limit_per_host} /></label>

      <h3 class="settings-group">Дополнительные источники (ключи API)</h3>
      <label>Ключ API Shodan
        <input type="password" bind:value={cfg.shodan_key} /></label>
      <label>Censys API ID
        <input type="password" bind:value={cfg.censys_id} /></label>
      <label>Секрет Censys
        <input type="password" bind:value={cfg.censys_secret} /></label>
      <label>Ключ API HaveIBeenPwned
        <input type="password" bind:value={cfg.hibp_key} /></label>
      <label>Токен GitHub (поиск по коду)
        <input type="password" bind:value={cfg.github_token} /></label>

      <h3 class="settings-group">Встроенные возможности (ничего устанавливать не нужно)</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.builtin_checks} />
        Встроенные проверки по шаблонам (открытые панели/файлы/конфиги — внутри программы)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.screenshots} />
        Скриншоты живых веб-хостов (через установленный Firefox или Chromium)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.favicon_hash} />
        Хэш favicon (mmh3 в стиле Shodan)
      </label>

      <h3 class="settings-group">Внешняя программа (необязательно)</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.nuclei} />
        Nuclei (если установлен в системе — дополнительные шаблоны)
      </label>

      <h3 class="settings-group">Уведомления (мониторинг)</h3>
      <label>Токен Telegram-бота
        <input type="password" bind:value={cfg.telegram_token} /></label>
      <label>ID чата Telegram
        <input type="text" bind:value={cfg.telegram_chat_id} />
        <span class="hint">Создайте бота (@BotFather), затем узнайте ID чата (@userinfobot).</span></label>
      <label>URL вебхука (необязательно)
        <input type="text" bind:value={cfg.webhook_url} placeholder="https://…" /></label>

      <div class="modal-actions">
        <button class="ghost" onclick={() => (open = false)}>Отмена</button>
        <button class="primary" onclick={save}>Сохранить</button>
      </div>
    </div>
  </div>
{/if}
