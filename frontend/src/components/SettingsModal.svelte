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
        app.flash("❌ O'z so'z ro'yxatingiz uchun fayl yo'lini kiriting");
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
      app.flash("✅ Sozlamalar saqlandi");
      open = false;
    } catch (e) {
      app.flash("❌ " + errMsg(e));
    }
  }
</script>

{#if open && cfg}
  <div class="modal-bg" role="presentation" onclick={() => (open = false)}>
    <div class="modal" role="dialog" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.key === "Escape" && (open = false)}>
      <h2>Sozlamalar</h2>
      <label>SecurityTrails API kalit
        <input type="password" bind:value={cfg.securitytrails_key} /></label>
      <label>VirusTotal API kalit
        <input type="password" bind:value={cfg.virustotal_key} /></label>
      <label>NVD API kalit (ixtiyoriy)
        <input type="password" bind:value={cfg.nvd_key} /></label>
      <label>nmap argumentlari
        <input type="text" bind:value={cfg.nmap_args} placeholder="-sV -T4 --top-ports 1000" /></label>
      <label>HTTP User-Agent
        <input type="text" bind:value={cfg.http_user_agent} placeholder="osint-forge/0.1 (+recon)" /></label>
      <label>Ko'rsatiladigan status kodlar
        <input type="text" bind:value={cfg.status_codes} placeholder="2xx,3xx,401,403,5xx" />
        <span class="hint">Masalan: 200,301,403 yoki 2xx,3xx,5xx · bo'sh = hammasi</span></label>
      <label>Parallellik (1–256)
        <input type="number" min="1" max="256" bind:value={cfg.max_concurrent} /></label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.fuzz_enabled} />
        Path fuzzing (jonli web host'larni yo'llar bo'yicha tekshirish)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.subdomain_bruteforce} />
        Subdomain bruteforce (DNS, 5000 nom)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.zone_transfer} />
        Zone transfer (AXFR) sinovi
      </label>
      <label>Fuzz wordlist (SecLists)
        <select bind:value={listChoice}>
          <option value="common">common (~4.7k, tez)</option>
          <option value="raft-directories">raft-directories (~30k)</option>
          <option value="raft-files">raft-files (~17k)</option>
          <option value="combo">combo (dirs+files)</option>
          <option value="custom">O'z faylim…</option>
        </select>
      </label>
      {#if listChoice === "custom"}
        <label>So'z ro'yxati fayli (to'liq yo'l)
          <input type="text" bind:value={listPath} placeholder="/home/user/wordlists/my.txt" />
          <span class="hint">Har qatorda bitta yo'l; # bilan boshlangan qator — izoh. Fayl o'qilmasa "common" ishlatiladi.</span></label>
      {/if}

      <h3 class="settings-group">Xavfsizlik / qamrov</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.scope_strict} />
        Scope guard — faqat nishon domen/IP'ga active skan (tavsiya etiladi)
      </label>
      <label>Qo'shimcha scope (har qatorda bitta domen yoki CIDR)
        <textarea rows="3" bind:value={scopeText} placeholder={"partner.org\n10.0.0.0/8"}></textarea>
        <span class="hint">Faqat yozma ruxsatingiz bor domen/tarmoqlarni qo'shing — ular ham aktiv skanlanadi.</span></label>
      <label>Scan vaqt chegarasi (daqiqa, 0 = cheksiz)
        <input type="number" bind:value={cfg.scan_timeout_min} /></label>
      <label>So'rov tezligi cheklovi (host uchun /sek, 0 = default)
        <input type="number" bind:value={cfg.rate_limit_per_host} /></label>

      <h3 class="settings-group">Qo'shimcha manbalar (API kalit)</h3>
      <label>Shodan API kalit
        <input type="password" bind:value={cfg.shodan_key} /></label>
      <label>Censys API ID
        <input type="password" bind:value={cfg.censys_id} /></label>
      <label>Censys secret
        <input type="password" bind:value={cfg.censys_secret} /></label>
      <label>HaveIBeenPwned API kalit
        <input type="password" bind:value={cfg.hibp_key} /></label>
      <label>GitHub token (kod qidiruvi)
        <input type="password" bind:value={cfg.github_token} /></label>

      <h3 class="settings-group">Ichki imkoniyatlar (hech narsa o'rnatish shart emas)</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.builtin_checks} />
        O'rnatilgan shablonli tekshiruv (ochiq panel/fayl/config — dastur ichida)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.screenshots} />
        Jonli web host'lar skrinshoti (tizimdagi Firefox yoki Chromium bilan)
      </label>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.favicon_hash} />
        Favicon hash (Shodan uslubida mmh3)
      </label>

      <h3 class="settings-group">Qo'shimcha tashqi dastur (ixtiyoriy)</h3>
      <label class="row">
        <input type="checkbox" bind:checked={cfg.nuclei} />
        Nuclei (agar tizimda alohida o'rnatilgan bo'lsa, qo'shimcha shablonlar)
      </label>

      <h3 class="settings-group">Bildirishnomalar (monitoring)</h3>
      <label>Telegram bot token
        <input type="password" bind:value={cfg.telegram_token} /></label>
      <label>Telegram chat ID
        <input type="text" bind:value={cfg.telegram_chat_id} />
        <span class="hint">Bot yarating (@BotFather), so'ng chat ID ni oling (@userinfobot).</span></label>
      <label>Webhook URL (ixtiyoriy)
        <input type="text" bind:value={cfg.webhook_url} placeholder="https://…" /></label>

      <div class="modal-actions">
        <button class="ghost" onclick={() => (open = false)}>Bekor</button>
        <button class="primary" onclick={save}>Saqlash</button>
      </div>
    </div>
  </div>
{/if}
