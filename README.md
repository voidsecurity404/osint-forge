# 🕸️ osint-forge

**osint-forge** — bitta nishon (domen yoki IP) atrofidagi butun internetga ochiq
tasvirni bir joyga yig'adigan, uni **jonli grafda** ko'rsatadigan va xavfsizlik
nuqtai nazaridan tahlil qiladigan razvedka (OSINT + recon) vositasi.

Siz bitta domen yoki IP kiritasiz — dastur o'nlab manbalardan subdomenlar,
IP'lar, portlar, servislar, sertifikatlar, texnologiyalar, URL'lar, email'lar,
ma'lum zaifliklar (CVE) va xavfsizlik topilmalarini yig'ib, ularni **Obsidian
uslubidagi grafga** chizadi. Topilgan har bir narsa qayerdan kelib chiqqani
bilan bog'langan bo'ladi, shuning uchun siz butun tasvirni bir qarashda
ko'rasiz.

Dastur **bitta Go dasturidan** iborat: ishga tushirsangiz, u ichida veb-server
ko'taradi va butun interfeys brauzerda `http://localhost:8081` da ochiladi.
Hech qanday tashqi dasturni o'rnatish shart emas — shablonli tekshiruvlar
dastur ichida, skrinshotlar tizimdagi brauzer bilan, qolgan hamma narsa sof
Go'da ishlaydi.

```
   domen / IP   ──▶   10+ manba   ──▶   jonli graf   ──▶   tahlil + hisobot
   example.com         DNS, crt.sh,      tugunlar va        teglar, CVE,
                       nmap, wayback…     bog'lanishlar      eksport, diff
```

> ⚠️ **Ogohlantirish:** aktiv skan (port-skan, HTTP so'rovlari, fuzzing)
> faqat **o'zingizga tegishli yoki yozma ruxsat berilgan** nishonlarga
> qaratilishi kerak. Ruxsatsiz skanlash ko'p mamlakatda qonunga ziddir.
> Passiv manbalar nishonga hech qanday paket yubormaydi.

---

## Mundarija

- [Nega osint-forge](#nega-osint-forge)
- [Tez boshlash](#tez-boshlash)
- [Qanday ishlaydi](#qanday-ishlaydi)
- [Skan bosqichlari](#skan-bosqichlari)
- [Ma'lumot manbalari](#malumot-manbalari)
- [Graf: tugun turlari](#graf-tugun-turlari)
- [Dastur ichidagi imkoniyatlar](#dastur-ichidagi-imkoniyatlar)
- [Veb-interfeys](#veb-interfeys)
- [CVE dvigateli](#cve-dvigateli)
- [Hisobotlar va eksport](#hisobotlar-va-eksport)
- [Uzluksiz monitoring](#uzluksiz-monitoring)
- [Xavfsizlik modeli](#xavfsizlik-modeli)
- [Sozlamalar va API kalitlar](#sozlamalar-va-api-kalitlar)
- [Ma'lumotlar qayerda saqlanadi](#malumotlar-qayerda-saqlanadi)
- [Buyruq qatori (CLI)](#buyruq-qatori-cli)
- [HTTP API](#http-api)
- [Qurish (build)](#qurish-build)
- [Testlar](#testlar)
- [Loyiha tuzilishi](#loyiha-tuzilishi)
- [Muammolarni hal qilish](#muammolarni-hal-qilish)
- [Ma'lum cheklovlar va tugallanmagan ishlar](#malum-cheklovlar-va-tugallanmagan-ishlar)
- [Litsenziya va mas'uliyat](#litsenziya-va-masuliyat)

---

## Nega osint-forge

Oddiy recon jarayonida siz o'nlab alohida vositalarni (subfinder, nmap, httpx,
nuclei, waybackurls…) ketma-ket ishga tushirasiz, natijalarni qo'lda
birlashtirasiz va matnli fayllardan ma'noni izlaysiz. **osint-forge** bularning
hammasini bitta dvigatel ostiga yig'adi va natijani **bog'langan graf** sifatida
ko'rsatadi, shuning uchun:

- **Bir qarashda tushuniladi** — qaysi IP qaysi domenga, qaysi port qaysi
  servisga, qaysi CVE qaysi servisga tegishli ekani ko'rinib turadi.
- **Takrorlanmaydi** — bir xil narsa turli manbadan topilsa, bitta tugunga
  birlashadi (deterministik ID: `ip:1.2.3.4`).
- **Xavfsiz** — ruxsat (consent) bo'lmasa hech qanday aktiv so'rov yuborilmaydi,
  va qamrov (scope) nishon chegarasidan chiqmaydi.
- **O'rganish uchun qulay** — har bir tugun uchun "nega muhim, qo'lda nimani
  tekshirish kerak, qaysi vosita bilan" degan o'zbekcha ko'rsatma bor.

---

## Tez boshlash

Eng oddiy yo'l — ichki `start.sh` skripti. U birinchi marta frontend va
serverni o'zi quradi, so'ng veb-serverni ishga tushiradi:

```sh
git clone https://github.com/voidsecurity404/osint-forge.git
cd osint-forge

./start.sh            # brauzerda: http://localhost:8081
```

`start.sh` buyruqlari:

| Buyruq                                | Nima qiladi                                                        |
| ------------------------------------- | ----------------------------------------------------------------- |
| `./start.sh`                          | Serverni ishga tushiradi (birinchi marta yoki kod o'zgargan bo'lsa avval quradi). |
| `./start.sh build`                    | Frontend + serverni qaytadan quradi.                             |
| `./start.sh dev`                      | Go server (`:8081`) + Vite "hot reload". Interfeys Vite manzilida (standart `http://localhost:5173`) ochiladi, `/api` so'rovlari 8081 ga proksilanadi. |
| `./start.sh run -open`                | Brauzerni avtomatik ochadi.                                      |
| `./start.sh run -addr 0.0.0.0:8081`   | Tarmoqdagi barcha interfeyslarda tinglaydi (**login yo'q!** — pastga qarang). |
| `./start.sh help`                     | Ichki yordamni chiqaradi.                                        |

`run` dan keyingi barcha argumentlar to'g'ridan-to'g'ri binary'ga uzatiladi.
Binary'ning o'zida faqat ikkita bayroq bor: `-addr` (standart `127.0.0.1:8081`)
va `-open`.

Standart holatda server faqat `127.0.0.1:8081` (shu kompyuter) da tinglaydi.
API boshqa saytlardan kelgan so'rovlarni rad etadi (CSRF himoyasi), shuning
uchun brauzeringizda ochiq boshqa veb-sahifalar uni boshqara olmaydi.

**Kerak bo'lgan narsalar:**

- **Ishga tushirish uchun** — hech narsa (bitta statik fayl).
- **Qurish uchun** — [Go 1.26+](https://go.dev) va [Node.js](https://nodejs.org)
  + npm (faqat interfeysni qurishga; natija binary'ga joylanadi).
- **Ixtiyoriy** — `nmap` (aniqroq servis versiyalari → aniqroq CVE), Chromium
  yoki Firefox (skrinshotlar), `nuclei` (qo'shimcha shablonlar). Ular bo'lmasa,
  tegishli bosqich o'tkazib yuboriladi yoki sof-Go zaxirasi ishlaydi.

### Nishon formatlari

Nishon maydoniga quyidagilarni kiritish mumkin — kiritilgan qiymat avval
normallashtiriladi:

| Kiritilgan                                   | Qanday talqin qilinadi                                   |
| -------------------------------------------- | -------------------------------------------------------- |
| `example.com`                                | Domen                                                    |
| `https://www.example.com:8443/login?x=1`     | `www.example.com` — sxema, port, yo'l va so'rov olib tashlanadi |
| `1.1.1.1`                                    | IPv4 manzil                                              |
| `2606:4700::1111`, `[2606:4700::1111]:443`   | IPv6 manzil                                              |
| `!!!`, `localhost`, `a..b`, `-x.com`         | **Rad etiladi** — TLD yo'q yoki domen buzuq             |

Domen kamida ikki qismdan (masalan `nom.tld`) iborat bo'lishi, TLD esa faqat
raqamdan iborat bo'lmasligi kerak. Interfeys nishonni qanday tushunishini
`GET /api/parse?target=…` orqali oldindan ko'rish mumkin.

---

## Qanday ishlaydi

osint-forge uchta qatlamdan iborat:

```
┌─────────────────────────────────────────────────────────┐
│  Brauzer (Svelte + Cytoscape.js)                         │
│  - graf, jadval, galereya, panellar                      │
└───────────────┬──────────────────────┬──────────────────┘
                │ JSON API (/api/*)     │ SSE (/api/events)
                │ so'rovlar             │ jonli yangilanishlar
┌───────────────▼──────────────────────▼──────────────────┐
│  Go veb-server (main.go, api.go, sse.go)                  │
│  - HTTP marshrutlar, hodisa uzatish (hub), SPA xizmati    │
└───────────────┬──────────────────────────────────────────┘
                │
┌───────────────▼──────────────────────────────────────────┐
│  Skan dvigateli (internal/)                               │
│  core · graph · recon · scan · cve · history · notes …    │
└───────────────────────────────────────────────────────────┘
```

- **Frontend** — Svelte 5 (runes) + Cytoscape.js grafi. Qurilgach
  (`frontend/dist`), to'liq holda Go binary'siga joylanadi (`go:embed`).
- **Veb-server** — har bir brauzer so'rovini JSON API orqali qabul qiladi,
  skan natijalarini **Server-Sent Events (SSE)** orqali jonli uzatadi.
- **Dvigatel** — har bir imkoniyat `core.Source` — kichik, mustaqil razvedka
  bo'lagi. Dvigatel ularni bosqichma-bosqich ishga tushiradi (pastga qarang).

Grafning markazida **konkurentlikka chidamli** ma'lumotlar modeli turadi.
Bir manbada xatolik (panic) yuz bersa, u ushlab olinadi va qayd qilinadi —
**butun skan hech qachon qulamaydi**, qolgan manbalar ishini davom ettiradi.

Bir vaqtda faqat **bitta** skan ishlaydi. Har bir yangi skan toza grafdan
boshlanadi; tugagach, natija avtomatik ravishda tarixga saqlanadi.

**Chidamlilik:**

- Server qayta ishga tushsa, oxirgi skan avtomatik qaytadi.
- Skan davomida sahifani yangilasangiz yoki ikkinchi tab ochsangiz, graf
  serverdan qayta sinxronlanadi. Server grafida endi yo'q tugunlar ekrandan
  olib tashlanadi — hech narsa yo'qolmaydi va eskisi ham qolib ketmaydi.
- Skan qayerdan boshlanmasin (shu tab, boshqa tab yoki monitoring), **barcha
  ochiq tablar** uni ko'radi va grafini tozalab, yangisini chizadi
  (`scan:start` hodisasi). Tarixdan scan ochilsa, boshqa tablar ham yangilanadi.
- Grafni o'qiydigan va unga yozadigan manbalar bir vaqtda ishlaganda ham
  ma'lumotlar modeli xavfsiz: o'qish har doim tugunning nusxasidan bo'ladi.
  Dastur race detector (`go test -race`) bilan sinalgan.

---

## Skan bosqichlari

Manbalar **olti bosqichda** ketma-ket, bosqich ichida esa **parallel** ishlaydi.
Avvalgi bosqich topgan narsani keyingisi ishlatadi:

```
 Discovery → Resolve → Probe → Web → Enrich → Post
 (passiv:    (nomlar   (aktiv:  (nostandart  (hosila: CVE,  (yakuniy tahlil:
  nom topish) → IP)     port,    portdagi     TLS, fuzz,     parametrlar)
                        HTTP)    web)         topilmalar)
```

1. **Discovery** — passiv manbalar nom va infratuzilmani topadi (DNS, RDAP,
   crt.sh, OTX, subdomain brute-force).
2. **Resolve** — topilgan host nomlari IP'ga aylantiriladi, shunda aktiv
   skanning aniq nishonlari bo'ladi.
3. **Probe** — aktiv manbalar topilgan narsalarni tekshiradi (port-skan, HTTP,
   reverse-IP, zone transfer). Shodan va Censys passiv bo'lsa-da shu bosqichda
   ishlaydi — ular topgan servis versiyalari CVE moslashtirishga yetib borishi
   uchun.
4. **Web** — nmap/port-skan topgan **nostandart portlardagi** (8080, 8443,
   3000…) web servislar ham probe qilinadi — ularga ham URL tugun, status
   kodi, fuzzing va tekshiruvlar tegadi.
5. **Enrich** — hosila tahlil: CVE moslashtirish, TLS, web tekshiruvlar,
   fuzzing, subdomain takeover, JS tahlili, built-in shablonlar, skrinshotlar,
   shuningdek Wayback, ASN, GitHub va HIBP.
6. **Post** — yakuniy tahlil hamma topilgan ustida ishlaydi: URL parametrlarini
   ajratib, ularni SQLi/XSS/redirect/LFI nomzodlari sifatida belgilaydi.

Har bir manbaning aniq bosqichi (qavs ichida — "Manbalar" panelida va loglarda
ko'rinadigan nomi):

| Bosqich       | Manbalar                                                                                     |
| ------------- | -------------------------------------------------------------------------------------------- |
| **Discovery** | `dns`, `whois/rdap`, `crt.sh`, `otx`, `subdomain-brute`                                       |
| **Resolve**   | `dns-resolve`                                                                                |
| **Probe**     | `nmap` *(yoki u bo'lmasa `portscan`)*, `http-probe`, `reverse-ip`, `zone-transfer`, `shodan`, `censys` |
| **Web**       | `http-ports`                                                                                 |
| **Enrich**    | `cve`, `tls`, `webchecks`, `checks`, `fuzz`, `takeover`, `js-analyze`, `robots/sitemap`, `screenshots`, `nuclei`, `wayback`, `asn`, `github`, `hibp` |
| **Post**      | `params`                                                                                     |

Kaliti yoki sozlamasi bo'lmagan manba (masalan, `shodan_key` bo'sh) skan
boshida ro'yxatdan butunlay chiqariladi va progressda hisoblanmaydi.

Skan to'xtatilsa yoki vaqt byudjeti tugasa, ishlab turgan manbalar keyingi
tekshiruv nuqtasida to'xtaydi. Natija **qisman** hisoblanadi: u saqlanadi
(monitoring skanlaridan tashqari), lekin monitoring uni "yo'qolgan narsalar"
sifatida taqqoslamaydi.

---

## Ma'lumot manbalari

### Passiv — nishonga paket yubormaydi (har doim ishlaydi)

| Manba             | Nima topadi                                                  | Kalit kerakmi           |
| ----------------- | ----------------------------------------------------------- | ----------------------- |
| **DNS**           | A/AAAA/MX/NS/TXT/CNAME yozuvlari + teskari DNS              | –                       |
| **RDAP / WHOIS**  | Ro'yxatdan o'tish ma'lumoti (zamonaviy WHOIS)              | –                       |
| **crt.sh**        | Sertifikat shaffofligi (CT) loglaridan subdomenlar          | –                       |
| **ASN (Cymru)**   | IP → avtonom tizim + BGP prefiks (Team Cymru DNS)          | –                       |
| **Wayback**       | Internet Archive'dan tarixiy URL/endpoint'lar (filtrlangan, HTTPS orqali) | –          |
| **OTX**           | Passiv-DNS host va IP'lar (AlienVault OTX) — IP'lar **tarixiy**, aktiv skanga kirmaydi | – |
| **Subdomain brute** | Ichki 5000 so'zlik ro'yxat bilan keng tarqalgan subdomenlar | –                   |
| **Parameters**    | Barcha URL'lardan query parametrlari, SQLi/XSS/redirect/LFI/SSRF/IDOR nomzodlariga ajratib | – |
| **Reverse-IP**    | Bitta IP'dagi boshqa domen va subdomenlar                   | SecurityTrails / VT     |
| **Shodan**        | Ochiq portlar, banner'lar, qo'shimcha hostlar               | Shodan                  |
| **Censys**        | Sertifikat va host ma'lumoti (Censys Search v2)             | Censys ID + secret      |
| **GitHub**        | Nishon haqida ochiq kod (sizib chiqqan config/kalit)        | GitHub token            |
| **CVE**           | Topilgan servis versiyalariga mos zaifliklar (pastga qarang) | – *(NVD kaliti ixtiyoriy)* |

> ASN uchun Team Cymru'ning **DNS** xizmati ishlatiladi — shunda nishon IP'si
> uchinchi tomonga ochiq HTTP so'rovida oshkor bo'lmaydi. Kalitsiz manbalar
> darhol ishlaydi; kalit talab qiladiganlari kalit bo'lmasa jimgina
> o'tkazib yuboriladi.
>
> **Reverse-IP, Shodan va Censys** faqat nishonning **o'z IP'lari** uchun
> so'raladi (pastdagi [qamrov qoidasi](#xavfsizlik-modeli)ga qarang). Domenning
> MX/NS serverlari (masalan, Google pochtasi, Cloudflare DNS) boshqa
> tashkilotniki — ular uchun so'rov API kvotasini yeb, grafni begona domenlar
> bilan to'ldirardi.
>
> **crt.sh** javobi oqim (stream) sifatida o'qiladi: juda katta domenlarda
> javob 64 MB chegarasida uzilsa ham, o'qilgan yozuvlar yo'qolmaydi.
> crt.sh vaqtincha xato qaytarsa (404/429/5xx — bepul xizmat tez-tez band
> bo'ladi), 2 va 5 soniyadan keyin qayta uriniladi. OTX so'rov limiti (429)
> xato emas, ogohlantirish sifatida ko'rsatiladi. ASN so'rovlari parallel
> bajariladi (real nishonda 16 IP: ~35 s → ~7 s).

### Aktiv — ruxsat (consent) talab qiladi

| Manba                 | Nima qiladi                                                             | Kerak                 |
| --------------------- | ----------------------------------------------------------------------- | --------------------- |
| **nmap**              | Servis/versiya aniqlash; portlar, servislar va CPE'lar. IPv4 va IPv6 alohida ishga tushiriladi (`-6`) | PATH'da `nmap` |
| **Port scan**         | Sof-Go zaxira skaner (banner grabbing bilan) — faqat nmap yo'q bo'lsa    | –                     |
| **HTTP probe**        | Jonli URL, status, sarlavha, aniqlangan texnologiyalar, email'lar        | –                     |
| **HTTP ports**        | nmap/port-skan topgan nostandart portdagi web servislar                  | –                     |
| **TLS checks**        | TLS 1.0/1.1 va muddati o'tgan/tez tugaydigan sertifikatlar (nostandart HTTPS portlarida ham) | – |
| **robots / sitemap**  | Server e'lon qilgan yo'llar (yolg'on ijobiysiz, host boshiga 100 tagacha); boshqa domendagi sitemap'lar o'tkazib yuboriladi | – |
| **Content fuzzing**   | Ichki SecLists bilan yo'l/kontent qidirish (soft-404 aqlli)             | –                     |
| **Web checks**        | CORS xatosi, ochiq `.git`/`.env`, katalog ro'yxati, xavfli metodlar      | –                     |
| **Built-in checks**   | Ochiq panel/fayllar uchun **dastur ichidagi** shablonli tekshiruv        | – *(ichida)*          |
| **JS analysis**       | Saytning JS fayllaridan endpoint va sizib chiqqan sirlarni ajratib olish | –                     |
| **CDN / WAF**         | Cloudflare, Akamai, Fastly, CloudFront, Sucuri, Azure Front Door, AWS ELB | – *(HTTP probe ichida)* |
| **Favicon hash**      | Shodan uslubidagi MurmurHash3 favicon hash                              | – *(HTTP probe ichida)* |
| **Takeover**          | Egasiz CNAME orqali subdomain-takeover ehtimolini aniqlash              | –                     |
| **Screenshots**       | Jonli web hostlar skrinshoti — **dastur ichida**                        | Chromium/Firefox      |
| **Zone transfer**     | Domen nom serverlariga qarshi AXFR urinishi                             | toggle                |
| **HIBP**              | HTTP probe yig'gan email'larni "Have I Been Pwned" bazasi bilan tekshirish | HIBP kalit         |
| **nuclei** *(ixtiyoriy)* | Tizimda alohida o'rnatilgan bo'lsa, ProjectDiscovery nuclei shablonlari | PATH'da `nuclei` + toggle |

Ichki so'z ro'yxatlari (SecLists qismlari) **binary'ga joylangan**, shuning
uchun fuzzing va brute-force hech qanday qo'shimcha yuklab olishsiz ishlaydi.

### Aktiv tekshiruvlar nimani qidiradi

- **Web checks** — CORS (begona `Origin` aks ettirilsa va credentials ruxsat
  etilsa — `high`; faqat aks ettirilsa yoki `*` credentials bilan kelsa —
  `medium`), ochiq `/.git/HEAD`, ochiq `/.env`, katalog ro'yxati
  (`Index of /`), `OPTIONS` orqali yoqilgan xavfli HTTP metodlar.
- **DNS (passiv)** — SPF va DMARC. SPF faqat pochta bilan ishlaydigan nomlar
  uchun talab qilinadi (asosiy domen yoki MX yozuvi bor nom). Subdomenning o'z
  DMARC yozuvi bo'lmasa, RFC 7489 bo'yicha asosiy domenning siyosati
  hisobga olinadi. DNS so'rovi xato bilan tugasa (timeout, SERVFAIL),
  "yozuv yo'q" degan yolg'on topilma chiqarilmaydi.
- **JS analysis** — AWS access key, Google API key, Slack token, GitHub token,
  Stripe live secret key, private key bloklari va JWT.
- **Takeover** — CNAME quyidagi servislardan biriga ko'rsatsa va javobda
  "egasiz resurs" belgisi bo'lsa: GitHub Pages, Heroku, AWS S3, Shopify,
  Fastly, Pantheon, Tumblr, Zendesk, Read the Docs, Surge.sh, Bitbucket.
- **Parameters** — parametr nomiga qarab toifalaydi: `sqli`, `xss`,
  `redirect`, `lfi/path`, `ssrf`, `idor`. Bu **nomzod**, tasdiqlangan zaiflik
  emas — qo'lda tekshirish kerak.
- **CDN / WAF** — host CDN ortida bo'lsa, siz skanlagan IP — bu **chekka
  (edge)** server, asl server emas. Port va host topilmalari CDN'ni tasvirlaydi.
- **Redirect'lar** — HTTP so'rovlari qamrovdagi hostlar orasida yo'naltirishga
  ergashadi (5 tagacha). Qamrovdan tashqaridagi hostga yo'naltirishga
  **ergashilmaydi**: 3xx javobning o'zi va uning `location` manzili yoziladi.
- **Fuzzing** — bir vaqtda 4 tagacha host tekshiriladi; har bir host uchun
  so'rov tezligi chegarasi (`rate_limit_per_host`) alohida amal qiladi.

---

## Graf: tugun turlari

Har bir tugun deterministik ID'ga ega (`<tur>:<kalit>`, masalan
`domain:example.com`, `ip:1.2.3.4`), shuning uchun bir narsa turli manbadan
topilsa ham bitta tugunga birlashadi va xususiyatlari qo'shib boriladi.

| Tur           | Ma'nosi                                                     |
| ------------- | ----------------------------------------------------------- |
| `domain`      | Asosiy domen (skan ildizi)                                  |
| `subdomain`   | Topilgan subdomen                                           |
| `ip`          | IPv4/IPv6 manzil                                            |
| `port`        | Ochiq port                                                  |
| `service`     | Port ortidagi servis va uning versiyasi                     |
| `technology`  | Aniqlangan texnologiya (server, framework, CMS…)            |
| `certificate` | TLS sertifikat                                              |
| `asn`         | Avtonom tizim / BGP prefiks                                 |
| `whois_org`   | Ro'yxatdan o'tgan tashkilot                                 |
| `url`         | Jonli URL yoki endpoint                                     |
| `email`       | Topilgan email manzil                                       |
| `cve`         | Ma'lum zaiflik                                              |
| `finding`     | Xavfsizlik topilmasi (noto'g'ri sozlama, oshkor resurs)     |
| `param`       | Sinash uchun URL query parametri                            |
| `bucket`      | Bulut saqlash bucket'i (S3/GCS/Azure) — *hali hech bir manba yaratmaydi, [pastga qarang](#malum-cheklovlar-va-tugallanmagan-ishlar)* |

Ikki tugun orasida faqat **bitta** yo'naltirilgan bog'lanish (edge) saqlanadi —
birinchi topilgan munosabat nomi qoladi. Bu grafda qalin "yelpig'ich"
chiziqlarning oldini oladi.

---

## Dastur ichidagi imkoniyatlar

Quyidagi uchta imkoniyat **standart yoqilgan** va **hech narsa o'rnatish
shart emas** — bu ularni tashqi dasturlardan farqlaydi:

- **Built-in checks (shablonli tekshiruv)** — ochiq Spring Actuator, phpinfo,
  Adminer, SQL dump, Swagger/OpenAPI, Go pprof, `.DS_Store`, WordPress va
  shunga o'xshash oshkor bo'lgan resurslarni topadi. Shablonlar (`.json`)
  binary ichiga joylangan; dvigatel nuclei uslubidagi minimal moslashtirgich
  (status/so'z/regex) bilan ishlaydi. Hamma tekshiruv **faqat o'qiydi** (GET),
  hech narsani buzmaydi. **Soft-404 himoyasi:** har bir host avval mavjud
  bo'lmagan tasodifiy yo'llar bilan kalibrlanadi. Har qanday yo'lga 200
  qaytaradigan (yoki so'ralgan yo'lni sahifada aks ettiradigan) saytlarda
  shablon "topilmasi" o'sha kalibrlash sahifasiga o'xshasa, u tashlab yuboriladi.
- **Screenshots** — tizimda mavjud **Chromium yoki Firefox** bilan jonli web
  hostlarning rasmini oladi (bir vaqtda 3 tagacha). Alohida brauzer o'rnatish
  shart emas; biror brauzer topilmasa, bu bosqich jimgina o'tkazib yuboriladi.
  Qidirish tartibi: avval Chromium oilasi (`chromium`, `chromium-browser`,
  `google-chrome`, `google-chrome-stable`, `chrome`, `chrome-headless-shell`,
  `brave-browser`), keyin Firefox oilasi (`firefox`, `firefox-esr`,
  `librewolf`). Firefox ochiq bo'lsa ham alohida nusxa ishlatiladi. Chromium
  **sandbox bilan** ishga tushiriladi (nishon sayti zararli bo'lishi mumkin);
  `--no-sandbox` faqat dastur root sifatida ishlaganda qo'shiladi. Rasm avval
  vaqtinchalik faylga yoziladi — muvaffaqiyatsiz urinish oldingi skanning
  rasmini buzmaydi. Skrinshotlar tafsilotlar panelidan **so'rov bo'yicha** ham
  olinadi (yuqoriga qarang). Bitta sahifa uchun bir vaqtda faqat bitta rasm
  olinadi (skan va panel bir sahifani so'rasa, natija umumiy), butun dasturda
  esa bir vaqtda eng ko'pi **4 ta** sahifa suratga olinadi.

### Tez skrinshot: doimiy Firefox (WebDriver BiDi)

Firefox bo'lsa, skrinshotlar **bitta doimiy headless Firefox** orqali
olinadi. U Firefox'ga o'rnatilgan WebDriver BiDi protokoli bilan boshqariladi,
qo'shimcha hech narsa o'rnatilmaydi. Har bir sahifa — shu brauzerdagi yangi
tab, butun brauzerni qayta ishga tushirish yo'q.

- **Sahifani kutish qoidasi:** sahifa to'liq yuklansa (`load`), darhol
  suratga olinadi. Biror resurs (treker, o'lik CDN, yopiq port) osilib qolsa,
  DOM tayyor bo'lgandan **3 soniya** o'tib, shu paytgacha chizilgan narsa
  olinadi. 15 soniyada DOM ham kelmasa, sahifa "javob bermadi" hisoblanadi.
- **Self-signed / noto'g'ri sertifikatli** saytlar ham suratga olinadi (recon
  nishonlarida keng tarqalgan).
- Firefox'ning o'z xato sahifasi (DNS topilmadi, ulanish rad etildi, TLS
  xatosi) skrinshot sifatida saqlanmaydi — bunday holatda aniq xato
  qaytariladi.
- Brauzer birinchi so'rovda ishga tushadi (~1–1.5 s), **3 daqiqa** ishlatilmasa
  yopiladi, qulasa avtomatik qayta ishga tushadi, server to'xtaganda yopiladi.
- BiDi ishlamasa (masalan, juda eski Firefox), avvalgi bir martalik
  `firefox --screenshot` usuli zaxira sifatida ishlaydi.

O'lchovlar (shu kompyuterdagi Firefox, mahalliy sahifalar):

| Holat | Avvalgi usul (har safar yangi brauzer) | Hozir |
| ----- | -------------------------------------- | ----- |
| Oddiy sahifa (brauzer ishlab turganda) | 0.6–3 s | **~0.3 s** |
| Bitta resursi osilib qolgan sahifa | 30–40 s, **rasm yo'q** | **~3 s, rasm bor** |
| 8 soniyalik sekin rasmi bor sahifa | ~8.6 s | ~3 s |
| Self-signed TLS sayt | brauzer xato sahifasi | **~0.25 s, haqiqiy sahifa** |
| 6 ta sahifa parallel | 6 ta alohida brauzer | **~0.6 s jami, bitta brauzer** |

Chromium uchun bir martalik usul qoladi, lekin unga 10 soniyalik qat'iy
chegara (`--timeout`) qo'yilgan: osilgan resurs rasmni bloklamaydi.
- **Favicon hash** — sof Go'da hisoblanadigan Shodan uslubidagi mmh3 hash
  (shu hash bilan Shodan'da `http.favicon.hash:<hash>` orqali bir xil
  faviconli boshqa hostlarni topish mumkin).

Haqiqiy tashqi `nuclei` tizimda bo'lsa, u ham **qo'shimcha** sifatida ishlaydi
(ixtiyoriy, standart o'chiq) — ya'ni dastur ichidagi tekshiruvlar ustiga
ProjectDiscovery'ning to'liq shablon to'plamini qo'shadi.

### Ichki shablonlar ro'yxati

| ID                     | Jiddiylik | Yo'l              | Nima topadi                         |
| ---------------------- | --------- | ----------------- | ----------------------------------- |
| `spring-actuator-env`  | high      | `/actuator/env`   | Spring Boot muhit o'zgaruvchilari   |
| `adminer`              | high      | `/adminer.php`    | Adminer DB paneli                   |
| `env-backup`           | high      | `/.env.bak`       | Config backup fayli                 |
| `sql-dump`             | high      | `/dump.sql`       | SQL dump fayli                      |
| `spring-actuator`      | medium    | `/actuator`       | Spring Boot Actuator                |
| `apache-server-status` | medium    | `/server-status`  | Apache `mod_status`                 |
| `phpinfo`              | medium    | `/phpinfo.php`    | `phpinfo()` sahifasi                |
| `go-pprof`             | medium    | `/debug/pprof/`   | Go pprof debug endpoint'i           |
| `ds-store`             | low       | `/.DS_Store`      | macOS `.DS_Store` fayli             |
| `swagger-api-docs`     | info      | `/swagger.json`   | Swagger/OpenAPI hujjati             |
| `graphql-endpoint`     | info      | `/graphql`        | GraphQL endpoint'i                  |
| `wordpress-login`      | info      | `/wp-login.php`   | WordPress                           |

### O'z shabloningizni qo'shish

Shablonlar `internal/scan/checks/` papkasidagi `.json` fayllardan olinadi
(fayl ichida massiv yoki bitta obyekt bo'lishi mumkin). Har bir shablon jonli
web host'ga **bitta GET so'rov** yuboradi va moslashtirgichlar o'tsa, topilma
yaratadi:

```json
[
  {
    "id": "spring-actuator-env",
    "name": "Spring Boot Actuator /env oshkor",
    "severity": "high",
    "path": "/actuator/env",
    "desc": "Spring Boot /actuator/env endpoint'i ochiq — muhit o'zgaruvchilari oshkor bo'ladi.",
    "matchers": [
      { "type": "status", "status": [200] },
      { "type": "word", "words": ["propertySources", "systemEnvironment"], "condition": "or", "part": "body" }
    ]
  }
]
```

| Maydon                 | Ma'nosi                                                           |
| ---------------------- | ----------------------------------------------------------------- |
| `id`, `name`, `desc`   | Identifikator, topilma sarlavhasi va tavsifi                      |
| `severity`             | `info`, `low`, `medium` yoki `high`                               |
| `path`                 | So'rov yuboriladigan yo'l                                         |
| `condition`            | Moslashtirgichlar **orasida**: `and` (standart) yoki `or`         |
| `matchers[].type`      | `status`, `word` yoki `regex`                                     |
| `matchers[].status` / `words` / `regex` | Tekshiriladigan qiymatlar                        |
| `matchers[].part`      | `body` (standart) yoki `header`                                   |
| `matchers[].condition` | Bitta moslashtirgich **ichida**: `or` (standart) yoki `and`       |
| `matchers[].negative`  | `true` — natijani teskari qiladi                                  |

Shablonlar `go:embed` orqali binary'ga joylanadi, shuning uchun yangi fayl
qo'shgach **qayta qurish** kerak (`make web`). Faqat o'qiydigan va zararsiz
tekshiruvlar qo'shing.

---

## Veb-interfeys

Interfeys haqiqiy pentest ish jarayoni uchun qurilgan:

- **Uch ko'rinish** — grafdan **jadval**ga (saralanadigan, qidiriladigan) va
  **skrinshot galereyasi**ga o'tish. Graf ustidagi qidiruv maydoni mos
  kelmaydigan tugunlarni yashiradi, mos kelganlarini ajratib ko'rsatadi.
- **Tugunlar bir-biriga tiqilmaydi** — graf qancha katta bo'lmasin, har bir
  tugun va uning yozuvi alohida turadi. Joylashuv alohida thread'da (Web
  Worker) hisoblanadi, shuning uchun sahifa muzlamaydi:
  1. Faqat bitta qo'shnisi bor "barg" tugunlar (CVE'lar, fuzz yo'llari,
     parametrlar, resolve bo'lmagan nomlar…) ota tuguni atrofida
     **konsentrik halqalarga** joylashadi, yozuvlari kengligiga qarab.
  2. Qolgan "yadro" graf **fCoSE** bilan joylashadi: avval spektral usul
     global tuzilmani topadi, keyin kuchlar uni sayqallaydi. Har bir tugun o'z
     halqasi uchun joyni oldindan band qiladi.
  3. Oxirida tugunlar **yozuvi bilan birga** to'rtburchak deb olinib,
     bir-biriga kirganlari markazlar chizig'i bo'ylab itarib ajratiladi.

  O'lchov: sun'iy 3671 tugunli grafda ustma-ust tushgan tugun juftlari
  3037 → **0**, yozuvlar 5879 → **0**; 631 tugunda 41/92 → **0/0**. Katta graf
  ~20–30 soniyada joylashadi. Bu vaqtda footer'da "🧭 Graf
  joylashtirilmoqda…" ko'rinadi va interfeys bilan ishlash mumkin. Graf
  kattalashsa, uni yaqinlashtirib (zoom) ko'ring — yozuvlar kichik masshtabda
  yashirinadi. "↻" tugmasi grafni noldan qayta joylashtiradi. Skan paytida
  graf bosqichma-bosqich, mavjud joylashuvni saqlagan holda yangilanadi.
  Skan tugagach esa butun graf bir marta noldan joylashtiriladi.
- **Status kodi bo'yicha ranglar** — HTTP javob bergan har bir tugun o'z status
  kodiga qarab bo'yaladi: **2xx** yashil · **3xx** ko'k · **401/403** binafsha
  · **4xx** sariq · **5xx** qizil. Burchakdagi bosiladigan "legenda" har bir
  sinfni ajratib ko'rsatadi. `401/403` va `5xx` — odatda eng qiziq joylar.
- **Tafsilotlar paneli** — tugunni ikki marta bossangiz (yoki jadvaldan
  tanlasangiz), uning barcha xususiyatlari chiqadi. URL tugunlari uchun sahifani
  shu yerning o'zida qayta so'rab, status, sarlavhalar va xom HTML'ni ko'rish
  mumkin.
- **Sahifa skrinshoti panelda** — "🌐 Brauzerda ochish" va "📄 HTML ko'rish"
  tugmalarining tagida o'sha sahifaning skrinshoti turadi. Rasmni bossangiz,
  u to'liq o'lchamda ochiladi; "🔄 Yangilash" sahifani qayta suratga oladi.
  - Saqlangan rasm bo'lsa, darhol ko'rsatiladi (nishonga so'rov ketmaydi).
  - Rasm bo'lmasa va skan bu sahifaga allaqachon so'rov yuborgan bo'lsa
    (statusi bor URL), skrinshot **avtomatik** olinadi (Firefox'da odatda
    1 soniyadan kam, osilgan resursli sahifada ~3 soniya).
  - Skan hech qachon so'rov yubormagan sahifalar (Wayback arxivi, sitemap, JS
    ichidan topilganlar) avtomatik ochilmaydi — passiv skan passiv qolishi
    uchun. Ular uchun "📸 Skrinshot olish" tugmasi chiqadi. Sozlamalarda
    skrinshotlar o'chirilgan bo'lsa ham shunday.
  - Host, port va topilma tugunlarida unga bog'langan sahifaning skrinshoti
    ko'rsatiladi.
  - Olingan rasm grafga ham yoziladi, shuning uchun galereyada va boshqa ochiq
    tablarda ham ko'rinadi.
- **Teglar va eslatmalar** — istalgan tugunni **Zaif / Tekshirildi / Qiziq /
  False positive** deb belgilash va matnli eslatma qo'yish mumkin. Teg tugun
  halqasini bo'yaydi; hammasi nishon bo'yicha saqlanadi va hisobotlarga tushadi.
  Eslatma har doim **ekrandagi grafning nishoniga** yoziladi — kiritish
  maydoniga boshqa nom yozib qo'ygan bo'lsangiz ham.
- **To'xtatish** — "To'xtatish" bosilgach, tugma server skanni haqiqatan
  tugatguncha "To'xtatilmoqda…" holatida qoladi. Shundan so'ng yangi skanni
  darhol boshlash mumkin.
- **"Keyingi qadam" o'quv rejimi** — har bir tugun uchun: *nega muhim*, *qo'lda
  nimani tekshirish kerak*, *qaysi vositalar bilan* (o'zbekcha). Dizayni bo'yicha
  faqat scope ichida sinashga undaydi.
- **Scan tarixi va vizual diff** — har bir tugagan skan avtomatik saqlanadi.
  Eski skanni qayta ochish yoki ikki skanni solishtirish mumkin: yangi
  tugunlar yashil halqa, yo'qolganlari qizil uzuq halqa bilan ko'rinadi.
- **Uzluksiz monitoring** — nishonni belgilangan oraliqda kuzatish; yangi
  subdomen, port yoki topilma chiqsa, **Telegram** yoki **webhook** orqali
  xabar keladi.
- **Manbalar paneli** — joriy skandagi har bir manba qancha vaqt olgani,
  holati (`running` / `done` / `error`) va nechta tugun/bog'lanish topgani.

---

## CVE dvigateli

Aniqlangan servis va versiyalar (nmap `-sV`, Shodan/Censys yoki web
sarlavhalaridan) ma'lum zaifliklarga moslashtiriladi:

- **NVD (National Vulnerability Database)** — CPE orqali servis versiyasiga
  mos CVE'larni topadi. NVD kaliti (ixtiyoriy) so'rov limitini oshiradi;
  kalitsiz so'rovlar NVD limitiga mos ravishda sekinlashtiriladi.
- **CISA KEV** — faol ekspluatatsiya qilinayotgan CVE'lar yorqin qizil halqa
  bilan belgilanadi (eng yuqori ustuvorlik).
- **EPSS** (FIRST.org) — har bir CVE uchun 30 kun ichida ekspluatatsiya
  ehtimoli foizi.
- **Lokal kesh** — natijalar sof-Go SQLite bazasida
  (`~/.cache/osint-forge/cve.sqlite`) keshlanadi: NVD natijalari **7 kun**,
  KEV ro'yxati **24 soat** yangi hisoblanadi. Shuning uchun takroriy skanlar
  tezroq va NVD limitiga kamroq tegadi. Baza WAL rejimida va kutish vaqti
  (busy timeout) bilan ochiladi, shuning uchun veb-server va `reconcli` uni
  bir vaqtda xatosiz ishlata oladi.
- **Shodan CVE'lari** — Shodan to'g'ridan-to'g'ri xabar qilgan CVE'lar ham KEV
  belgisi va EPSS bali bilan boyitiladi.

Servis haqida ma'lumot juda kam bo'lsa (masalan, versiya aniqlanmagan), noto'g'ri
mosliklar bilan grafni to'ldirmaslik uchun moslashtirish o'tkazib yuboriladi.

Natijada siz "qaysi CVE eng avval e'tibor talab qiladi"ni og'irlik + KEV + EPSS
bo'yicha ko'rasiz, shunchaki ro'yxat emas.

---

## Hisobotlar va eksport

Eksport menyusidan (yoki CLI'da tegishli bayroqlar bilan) olti formatda:

| Format        | Nima uchun                                                       |
| ------------- | --------------------------------------------------------------- |
| **HTML**      | Mustaqil, chiroyli hisobot — brauzerda ochib ko'rsatish uchun.  |
| **Markdown**  | Obsidian/Notion yoki Git repo uchun matnli hisobot.             |
| **CSV**       | Topilmalar + CVE jadvali — Excel/skript uchun.                  |
| **SARIF 2.1.0** | CI / kod-skanerlash panellari (GitHub Code Scanning) uchun. Har bir natijada joylashuv (ta'sirlangan URL/host) bor; har bir topilma turi — alohida qoida; CVE'lar CVSS bo'yicha `security-severity` oladi. |
| **JSON**      | To'liq graf — boshqa vositaga uzatish uchun.                    |
| **Obsidian vault (.zip)** | Har bir tugun — alohida, o'zaro bog'langan nota.   |

Qo'ygan **teglaringiz va eslatmalaringiz** HTML, Markdown, JSON, CSV va Obsidian
hisobotlariga ham qo'shiladi — ya'ni hisobot sizning qo'lda qilgan tahlilingizni
ham o'z ichiga oladi.

Eksport har doim **joriy** grafdan olinadi. Eski skanning hisobotini olish
uchun avval uni tarixdan oching. CLI hisobotlarida teg va eslatmalar bo'lmaydi —
ular faqat veb-interfeys eksportiga qo'shiladi. HTML hisobot faqat `http(s)`
havolalarni bosiladigan qiladi.

---

## Uzluksiz monitoring

🔔 paneldan nishonni kuzatuvga qo'shasiz va oraliqni tanlaysiz (**5 daqiqa,
1 soat, 6 soat, 12 soat yoki 1 kun**). Dastur fonda o'sha nishonni qayta
skanlaydi va natijani oldingisi bilan solishtiradi. **O'zgarish bo'lsa**
(yangi subdomen/port/topilma yoki yo'qolgan narsa) — Telegram yoki webhook
orqali qisqa xabar yuboradi:

```
🕸️ osint-forge — example.com da o'zgarish
+2 yangi, −1 yo'qolgan
➕ subdomain: new.example.com
➕ port: 8080/tcp
➖ url: http://example.com/old
```

Sozlash: Sozlamalar → "Bildirishnomalar" bo'limida Telegram bot token va chat
ID (yoki webhook URL) kiriting. "✈ Test xabar" tugmasi bilan tekshiring.

### Xabar filtri

Har bir kuzatuvda **qaysi o'zgarishlar xabar yuborishini** tanlaysiz
("Xabar" maydoni). Shunda Telegram yangi arxiv URL yoki texnologiya kabi
ahamiyatsiz o'zgarishlar bilan to'lib ketmaydi:

| Tanlov | Nima haqida xabar keladi |
| ------ | ------------------------ |
| **Muhim o'zgarishlar** *(standart)* | Yangi/yo'qolgan subdomen, IP, ochiq port, servis, sertifikat, CVE va topilmalar. URL, parametr, texnologiya, email kabi "shovqin" kirmaydi. |
| **Faqat xavfli** | Faqat **high/critical** topilmalar va CVE'lar (CISA KEV'dagi CVE har doim critical hisoblanadi) hamda yangi ochiq portlar; faqat yangilar. |
| **Hamma o'zgarishlar** | Grafdagi har qanday o'zgarish (oldingi xatti-harakat). |
| **O'zim tanlayman…** | Turlarni belgilaysiz (subdomen, IP, port, servis, topilma, CVE, sertifikat, URL, parametr, texnologiya, email, ASN/WHOIS), topilma/CVE uchun **minimal jiddiylikni** tanlaysiz va xohlasangiz **faqat yangilar** haqida xabar olasiz. |

- Ro'yxatda har bir kuzatuv tagida uning filtri qisqacha ko'rinadi (🔎).
  **✏️** tugmasi kuzatuvni formaga qaytaradi: oraliq va filtrni o'zgartirib,
  "Saqlash" bosilsa, o'sha kuzatuv yangilanadi (dublikat yaratilmaydi).
- O'zgarish bo'lsa-yu, hech biri filtrga mos kelmasa, xabar yuborilmaydi.
  Panelda esa "+N / −M o'zgarish bor, lekin filtrga mos emas" deb yoziladi.
- Xabarda faqat filtrdan o'tgan o'zgarishlar sanaladi va ko'rsatiladi.
- Filtrsiz yaratilgan eski kuzatuvlar avvalgidek hamma o'zgarishlar haqida
  xabar beradi.

Telegram bot: [@BotFather](https://t.me/BotFather) orqali bot yaratasiz, chat
ID ni esa [@userinfobot](https://t.me/userinfobot) beradi.

**Qanday ishlaydi:**

- Kuzatuvlar `~/.config/osint-forge/monitor.json` ga saqlanadi va server qayta
  ishga tushganda tiklanadi.
- Rejalashtirgich har daqiqada tekshiradi. Birinchi monitoring skani kuzatuv
  qo'shilgandan keyin **bir oraliq o'tgach** boshlanadi. API orqali istalgan
  oraliqni berish mumkin, lekin u kamida 5 daqiqa bo'ladi.
- Bir vaqtda bitta skan: boshqa skan ketayotgan bo'lsa, navbatdagi kuzatuv
  keyingi daqiqada qayta uriniladi (jadvali bir oraliqqa surilib ketmaydi).
- Kuzatuvga qo'shishda ruxsat (consent) belgilansa, monitoring **aktiv** skan
  qiladi; aks holda faqat passiv manbalar ishlaydi.
- Yangi skan nishonning tarixdagi **oxirgi** skani bilan taqqoslanadi (qo'lda
  qilingan skanlar ham hisobga kiradi). O'zgarish bo'lmasa, xabar yuborilmaydi —
  panelda "o'zgarishsiz" yoziladi.
- To'xtatilgan yoki vaqt byudjetiga sig'magan monitoring skani **saqlanmaydi va
  taqqoslanmaydi** — aks holda u ko'ra olmagan hamma narsa "yo'qolgan" bo'lib
  yolg'on xabar ketardi. Panelda "skan to'liq tugamadi" yoziladi.
- Xabarda 15 tagacha yangi va jami 25 tagacha qator bo'ladi (Telegram'da
  4000 belgidan uzun xabar qisqartiriladi).
- Xabar yuborilmasa, sababi panelda ko'rinadi (Telegram'ning izohi bilan,
  masalan "chat not found"). Xato matnlarida bot tokeni va webhook yo'li
  hech qachon ko'rsatilmaydi.
- **Webhook formati:** `POST` so'rov, `Content-Type: application/json`, tana
  `{"text": "…xabar…"}`. Bu Slack va Mattermost "incoming webhook"lari bilan
  to'g'ridan-to'g'ri mos keladi. Discord `content` maydonini kutadi, shuning
  uchun u uchun oraliq adapter kerak.

**Bilish kerak:** monitoring skani oddiy skan kabi ishlaydi — u barcha ochiq
tablarda **joriy grafni almashtiradi** (ekranda qisqa "Monitoring skani
boshlandi" xabari chiqadi).

---

## Xavfsizlik modeli

osint-forge "fail-safe" (xato bo'lsa xavfsiz tomonga) tamoyili bilan qurilgan:

- **Qamrov qo'riqchisi (`scope_strict`, standart yoqilgan)** — aktiv so'rovlar
  faqat nishonning asosiy domeni, uning subdomenlari va **nishonning o'z
  IP'lari**ga tegadi (qoida pastda). Reverse-IP, umumiy hosting, sertifikat
  SAN'lari, MX/NS yozuvlari keltirib chiqargan begona hostlar **hech qachon**
  aktiv skanlanmaydi — ular boshqa tashkilotniki. Qo'shimcha domen/CIDR'larni
  `extra_scope` orqali qo'shish mumkin. Qamrov HTTP redirect'lariga ham
  tatbiq etiladi.
- **Ruxsat darvozasi (consent)** — butun aktiv manbalar to'plami siz
  avtorizatsiyani tasdiqlamaguningizcha umuman ishga tushmaydi (interfeysda
  belgilash, CLI'da `-active`).
- **Nishon validatsiyasi** — noto'g'ri kiritilgan nishon (`!!!`, TLD'siz so'z,
  buzuq domen) rad etiladi, bekorchi skan boshlanmaydi.
- **Skan byudjeti (`scan_timeout_min`)** — umumiy qattiq vaqt chegarasi; skan
  hech qachon cheksiz ishlamaydi.
- **So'rov tezligi (`rate_limit_per_host`)** — fuzzing/brute-force host'ga
  sekundiga nechta so'rov yuborishini cheklaydi (standart 40), DoS'ga
  o'xshamaslik uchun.
- **CSRF himoyasi** — API cross-origin/cross-site so'rovlarni (`Origin` va
  `Sec-Fetch-Site` sarlavhalari bo'yicha) rad etadi; brauzeringizda ochiq
  begona sayt serverni boshqara olmaydi. Javoblar `X-Frame-Options: DENY` va
  `X-Content-Type-Options: nosniff` bilan yuboriladi.
- **Fayl yo'li himoyasi** — skrinshot endpoint'i faqat skrinshot papkasidagi
  fayllarni beradi, tarix ID'lari faqat raqamdan iborat bo'lishi tekshiriladi
  (path traversal'ga yo'l yo'q).
- **Maxfiy ma'lumotlar** — `config.json` (API kalitlari), eslatmalar va
  `monitor.json` faqat egasi o'qiy oladigan `0600` huquq bilan atomik yoziladi.
  URL'dagi API kalitlari (Shodan), Telegram bot tokeni va webhook yo'llari xato
  xabarlari va loglarga hech qachon tushmaydi.
- **Brauzer sandbox'i** — skrinshot uchun Chromium renderer sandbox'i yoqilgan
  holda ishlaydi (faqat root'da o'chiriladi).
- **Sozlamalar validatsiyasi** — formadan kelgan qiymatlar tozalanadi va
  cheklanadi (`max_concurrent` 1–256, manfiy sonlar 0 ga, bo'sh User-Agent
  standartga), shunda noto'g'ri qiymat yuz minglab ulanish ochib yubormaydi.
- **Faqat lokal** — server standart holatda faqat `127.0.0.1` da tinglaydi.

> **Qamrov qanday hisoblanadi:**
>
> - **Host nomlari** — **ro'yxatdan o'tgan domen** (eTLD+1) bo'yicha. Ya'ni
>   `api.example.com` ni kiritsangiz, aktiv skan butun `*.example.com` ga
>   ruxsat oladi — agar sizga faqat bitta subdomen ruxsat etilgan bo'lsa, buni
>   hisobga oling.
> - **IP manzillar** — faqat (1) nishonning o'zi bo'lgan IP, (2) `extra_scope`
>   dagi CIDR ichidagi IP, yoki (3) shu skan davomida **qamrovdagi host nomi
>   jonli DNS orqali resolve qilingan** IP. Domenning MX/NS/CNAME serverlari
>   ham resolve qilinadi va grafda ko'rinadi, lekin ular qamrovdagi nom
>   bo'lmagani uchun ularning IP'lari aktiv skanlanmaydi. Passiv DNS (OTX)
>   bergan **tarixiy** IP'lar ham skanlanmaydi — ular hozir boshqaning
>   serveri bo'lishi mumkin. nmap/port-skan loglarida "N IP qamrovdan
>   tashqarida" deb yoziladi.

> **Diqqat:** `-addr 0.0.0.0:8081` bilan ishga tushirsangiz, server tarmoqqa
> ochiladi va **login yo'q** — tarmoqdagi istalgan odam sizning nomingizdan
> skan boshlay oladi va API kalitlaringizni o'qiy oladi. Buni faqat ishonchli,
> yakka tarmoqda qiling.

---

## Sozlamalar va API kalitlar

Sozlamalarni interfeysning ⚙ panelidan yoki to'g'ridan-to'g'ri diskdagi
`config.json` fayldan tahrirlash mumkin. Barcha kalitlar interfeysda bor
(qo'shimcha scope — har qatorda bitta; o'z so'z ro'yxatingiz — "O'z faylim…"
tanlovi orqali). Saqlashda qiymatlar tozalanadi va cheklanadi.

| Kalit                      | Standart                    | Ma'nosi                                          |
| -------------------------- | --------------------------- | ------------------------------------------------ |
| `nmap_args`                | `-sV -T4 --top-ports 1000`  | Qo'shimcha nmap bayroqlari                       |
| `http_user_agent`          | `osint-forge/0.1 (+recon)`  | HTTP so'rovlardagi User-Agent                    |
| `max_concurrent`           | `16`                        | Parallel ishchilar soni (1–256)                  |
| `fuzz_enabled`             | `true`                      | Yo'l fuzzing                                     |
| `fuzz_wordlist`            | `common`                    | Fuzzing so'z ro'yxati (pastga qarang)            |
| `subdomain_bruteforce`     | `true`                      | DNS subdomain brute-force (5000 nom)             |
| `zone_transfer`            | `true`                      | AXFR sinovi (faqat aktiv rejimda)                |
| `status_codes`             | `2xx,3xx,401,403,405,5xx`   | Qaysi HTTP status kodlarini yozish (pastga qarang) |
| `scan_timeout_min`         | `30`                        | Skan vaqt chegarasi (daqiqa, 0 = cheksiz)        |
| `scope_strict`             | `true`                      | Qamrov qo'riqchisi                               |
| `extra_scope`              | `[]`                        | Qo'shimcha domen va CIDR'lar (`10.0.0.0/8`)      |
| `rate_limit_per_host`      | `0` (= 40 so'rov/s)         | Host uchun sekundiga maksimal so'rov             |
| `builtin_checks`           | `true`                      | Ichki shablonli tekshiruvlar                     |
| `screenshots`              | `true`                      | Skrinshotlar                                     |
| `favicon_hash`             | `true`                      | Favicon hash                                     |
| `nuclei`                   | `false`                     | Tashqi nuclei'ni ham ishlatish                   |
| `telegram_token` / `telegram_chat_id` / `webhook_url` | – | Monitoring bildirishnomalari                   |
| `nvd_key`                  | –                           | NVD API kaliti (CVE limitini oshiradi)           |
| `shodan_key`               | –                           | Shodan API kaliti                                |
| `censys_id` / `censys_secret` | –                        | Censys Search v2 ma'lumotlari                    |
| `securitytrails_key` / `virustotal_key` | –              | Reverse-IP manbalari                             |
| `hibp_key`                 | –                           | Have I Been Pwned kaliti                         |
| `github_token`             | –                           | GitHub kod qidiruvi tokeni                       |

Kalitlar **ixtiyoriy** — ularsiz dastur ishlaydi, shunchaki o'sha kalitga
bog'liq manba o'tkazib yuboriladi.

**`fuzz_wordlist` qiymatlari:**

| Qiymat               | Ro'yxat                                                   |
| -------------------- | -------------------------------------------------------- |
| `common`             | SecLists `common.txt` (~4 750 yo'l)                      |
| `raft-directories`   | SecLists `raft-medium-directories.txt` (~30 000 yo'l)    |
| `raft-files`         | SecLists `raft-medium-files.txt` (~17 000 yo'l)          |
| `combo`              | Ikkala raft ro'yxati birga, takrorlarsiz                 |
| `/yo'l/ro'yxat.txt`  | O'zingizning faylingiz: har qatorda bitta yo'l, `#` bilan boshlangan qator — izoh. Fayl o'qilmasa, `common` ishlatiladi. |

**`status_codes` sintaksisi:** vergul bilan ajratilgan ro'yxat — aniq kod
(`200`), oraliq (`200-299`) yoki sinf (`2xx`). Bo'sh qiymat — barcha kodlar.
Standart qiymat 404 javoblarni chiqarib tashlaydi.

> Config fayli eski versiyada yozilgan bo'lsa va unda yangi ichki imkoniyatlar
> (`builtin_checks`, `screenshots`, `favicon_hash`) kaliti bo'lmasa, ular
> o'chib qolmaydi — standart qiymat (yoqilgan) saqlanadi.

---

## Ma'lumotlar qayerda saqlanadi

Hamma narsa sizning kompyuteringizda, standart OS papkalarida saqlanadi
(Linux misolida; `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` hisobga olinadi):

| Nima                 | Yo'l                                                     |
| -------------------- | -------------------------------------------------------- |
| Sozlamalar           | `~/.config/osint-forge/config.json`                      |
| Teglar/eslatmalar    | `~/.config/osint-forge/notes/<nishon>.json`              |
| Monitoring kuzatuvlari | `~/.config/osint-forge/monitor.json`                   |
| Scan tarixi          | `~/.cache/osint-forge/history/<nishon>/<unix-nano>.json` (+ haqiqiy nishon nomi `.target` faylida) |
| Skrinshotlar         | `~/.cache/osint-forge/screenshots/`                      |
| CVE keshi (SQLite)   | `~/.cache/osint-forge/cve.sqlite` (+ `-wal`/`-shm` fayllari) |

macOS'da `~/.config` o'rniga `~/Library/Application Support`, `~/.cache`
o'rniga `~/Library/Caches`; Windows'da mos ravishda `%AppData%` va
`%LocalAppData%` ishlatiladi.

- **Tarix o'z-o'zidan cheksiz o'smaydi:** yangi skan oldingisi bilan aynan bir
  xil tugunlardan iborat bo'lsa, eski nusxa yangisi bilan almashtiriladi
  (shuning uchun tez-tez ishlaydigan monitoring diskni to'ldirmaydi). Har bir
  nishon uchun eng ko'pi **200** ta skan saqlanadi, eng eskilari avtomatik
  o'chiriladi. Keraksizlarini tarix panelidan ham o'chirish mumkin; nishonning
  oxirgi skani o'chirilsa, nishon ro'yxatdan ham chiqadi.
- Tarixni ko'rish (ro'yxat, diff) hech qachon bo'sh papka yaratmaydi.
  IPv6 nishonlar ham tarixdan to'g'ri nomi bilan ochiladi.
- Server ishga tushganda eng oxirgi skanlangan nishonning oxirgi skani
  avtomatik ochiladi.
- Butun holatni nolga qaytarish uchun yuqoridagi `osint-forge` papkalarini
  o'chirish kifoya.

Hech qanday ma'lumot tashqi serverga yuborilmaydi (API kaliti bilan siz
yoqqan manbalar va monitoring bildirishnomalaridan tashqari).

---

## Buyruq qatori (CLI)

Grafik interfeyssiz, avtomatlashtirish va CI uchun `reconcli` xuddi shu
dvigateldan va xuddi shu manbalar to'plamidan foydalanadi:

```sh
make cli                                  # build/bin/reconcli

reconcli example.com                      # faqat passiv OSINT
reconcli -active example.com              # + aktiv skan (faqat ruxsatli nishon!)
reconcli -active -diff example.com        # skanni saqlab, o'zgarishlarni chiqaradi
reconcli -active -html rep.html example.com   # HTML hisobot yozadi
reconcli -obsidian ./vault example.com    # Obsidian vault'ga eksport
reconcli -quiet -sarif out.sarif -json out.json example.com   # CI uchun
```

| Bayroq            | Ma'nosi                                                     |
| ----------------- | ---------------------------------------------------------- |
| `-active`         | Aktiv skanni ham ishga tushiradi (faqat ruxsatli nishon)  |
| `-quiet`          | Har bir tugun chiqishini bostiradi                         |
| `-timeout 30m`    | Umumiy skan byudjeti (0 = config'dan)                     |
| `-no-scope`       | Qamrov qo'riqchisini o'chiradi (**XAVFLI**)               |
| `-diff`           | Skanni saqlab, oldingisiga nisbatan o'zgarishni bosib chiqaradi |
| `-json` / `-md` / `-csv` / `-sarif` / `-html` `FAYL` | Tegishli formatda hisobot yozadi |
| `-obsidian DIR`   | Obsidian vault'ni shu papkaga yozadi                      |

**Bilish foydali:**

- Bayroqlar nishondan **oldin** yozilishi kerak: `reconcli -active example.com`
  ishlaydi. `reconcli example.com -active` yozilsa, dastur buni aniq xabar
  bilan tushuntiradi va 2 kodi bilan chiqadi.
- Nishon veb-interfeys kabi tekshiriladi: `foo`, `!!!` kabi noto'g'ri
  qiymatlar rad etiladi (chiqish kodi 2).
- Jonli loglar va topilgan tugunlar **stderr**'ga, yakuniy xulosa (har bir
  tugun turi bo'yicha son va jami) **stdout**'ga chiqadi. Shuning uchun
  `reconcli example.com > natija.txt` faylga faqat toza xulosani yozadi.
- **Ctrl+C** skanni yumshoq to'xtatadi: shu paytgacha topilgani chiqariladi va
  so'ralgan hisobotlar baribir yoziladi (natija qisman ekani ogohlantiriladi).
- CLI sozlamalarni veb-interfeys bilan bir xil `config.json` dan o'qiydi.
- CLI skanni tarixga faqat `-diff` bilan saqlaydi. Bu skanlar umumiy papkaga
  yoziladi, shuning uchun veb-interfeys tarixida ham ko'rinadi. Qisman
  (to'xtatilgan/vaqti tugagan) skan `-diff` bilan saqlanmaydi va dastur 1 kodi
  bilan chiqadi.

---

## HTTP API

Veb-interfeys quyidagi JSON API ustiga qurilgan (hammasi same-origin).
Agar o'z vositangizni yozmoqchi bo'lsangiz foydali:

| Metod + yo'l                              | Nima qiladi                               |
| ----------------------------------------- | ----------------------------------------- |
| `GET /api/events`                         | SSE oqimi: `scan:start/delta/log/progress/timing`, `graph:reset` |
| `GET /api/status`                         | Skan ishlayaptimi va qaysi nishon         |
| `GET /api/parse?target=`                  | Nishon qanday talqin qilinishini oldindan ko'rish |
| `POST /api/scan`                          | Skan boshlash (`{target, consent}`)       |
| `POST /api/cancel`                        | Joriy skanni to'xtatish                    |
| `GET /api/snapshot`                       | To'liq joriy graf                          |
| `GET /api/diff?target=`                   | Nishonning tarixdagi oxirgi ikki skani farqi (`added` / `removed`) |
| `GET /api/config` · `PUT /api/config`     | Sozlamalarni o'qish / saqlash             |
| `GET /api/nmap`                           | `nmap` o'rnatilganmi (`true` / `false`)   |
| `GET /api/page?url=`                      | Bitta URL'ni olib, status/sarlavha/HTML ko'rsatish |
| `GET /api/timings`                        | Manbalar vaqtlari                          |
| `GET /api/history`                        | Skanlangan nishonlar ro'yxati             |
| `GET /api/history/{target}`               | Nishonning saqlangan skanlari             |
| `GET /api/history/{target}/compare?from=&to=` | Ikki skanni solishtirish (bo'sh `from` = `to` dan oldingisi, bo'sh `to` = eng oxirgisi) |
| `POST /api/history/{target}/{id}/open`    | Eski skanni ochish                        |
| `DELETE /api/history/{target}/{id}`       | Skanni o'chirish                          |
| `GET /api/notes?target=` · `PUT /api/notes` | Teg/eslatmalarni o'qish / saqlash (`{target, node, tags, text}`) |
| `GET /api/monitor` · `POST /api/monitor` · `DELETE /api/monitor/{target}` | Monitoring kuzatuvlari (`{target, intervalMin, consent, filter?, preset?}` — `filter`: `{types, minSeverity, ignoreRemoved}`, `preset`: `important`/`critical`/`all`) |
| `POST /api/notify/test`                   | Test bildirishnoma yuborish               |
| `GET /api/export/{format}?target=`        | Hisobot yuklab olish (`json`/`html`/`md`/`csv`/`sarif`/`obsidian`) |
| `GET /api/screenshot?path=`               | Olingan skrinshotni ko'rsatish            |
| `POST /api/screenshot`                    | URL tugunining skrinshoti (`{url, force?, auto?}`): saqlangan bo'lsa darhol, bo'lmasa olib qaytaradi → `{url, path, takenAt, cached}` |

- `POST`/`PUT` so'rovlari `Content-Type: application/json` talab qiladi, tana
  hajmi 1 MiB gacha.
- Xatolar `{"error": "…"}` ko'rinishida qaytadi.
- `{target}` yo'l qismi istalgan ko'rinishda bo'lishi mumkin
  (`https://Example.com/x` → `example.com`); saqlangan skani yo'q nishon uchun
  `404` va tushunarli xabar qaytadi.
- SSE hodisalari: `scan:start` (`{target, consent, monitor}` — skan boshlandi,
  grafni tozalang), `scan:delta` (yangi tugun/bog'lanishlar), `scan:log`,
  `scan:progress` (`finished: true` — skan tugadi), `scan:timing`,
  `graph:reset` (server grafi almashtirildi — `/api/snapshot` ni qayta oling).
- Teg kalitlari: `vuln`, `checked`, `interesting`, `fp`. Eslatma matni 20 000
  belgigacha; teg ham, matn ham bo'sh bo'lsa, eslatma o'chiriladi.
- `POST /api/screenshot`: faqat `http(s)` URL va faqat joriy grafdagi URL
  tugunlari uchun yangi rasm olinadi (aks holda `400`/`404`). `auto: true`
  bo'lsa, server skan so'rov yubormagan sahifa uchun yoki skrinshotlar
  o'chirilganda `409` qaytaradi (UI shunda tugma ko'rsatadi). Brauzer
  yo'q — `501`, vaqt tugadi — `504`.

Misol — terminaldan passiv skan boshlash va jonli hodisalarni kuzatish:

```sh
curl -s -X POST http://127.0.0.1:8081/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","consent":false}'

curl -N http://127.0.0.1:8081/api/events          # SSE oqimi
curl -s http://127.0.0.1:8081/api/snapshot > graf.json
```

---

## Qurish (build)

**Ishga tushirish uchun** hech narsa kerak emas — binary o'zi yetarli
(SQLite sof-Go, so'z ro'yxatlari va shablonlar binary ichida).

**Qurish uchun:** [Go 1.26+](https://go.dev) va [Node.js](https://nodejs.org) + npm.

```sh
make            # = make all: test + vet + build
make frontend   # Svelte UI'ni frontend/dist ga quradi (binary'ga joylanadi)
make web        # frontend + build/bin/osint-forge → embed qilingan veb-server
make run        # qurib, http://127.0.0.1:8081 da ishga tushiradi
make cli        # build/bin/reconcli → buyruq qatori versiyasi
make build      # cli + web
make test       # go test ./...       (barcha paketlar, veb-server testlari bilan)
make race       # go test -race ./... (CI'dagi kabi; cgo kerak)
make vet        # go vet ./...
make fmt        # go fmt ./...
make tidy       # go mod tidy
make clean      # build/bin ni o'chiradi
```

Yoki `start.sh` orqali: `./start.sh build`, `./start.sh dev`, `./start.sh run`.
`./start.sh` (yoki `run`) Go/UI manba kodi binary'dan yangiroq bo'lsa, uni
**avtomatik qayta quradi** — kod o'zgargandan keyin eski build ishlab qolmaydi.
`go` yoki `npm` topilmasa, aniq xabar beradi.

> Server binary'si `frontend/dist` ni `go:embed` orqali o'z ichiga oladi,
> shuning uchun `go build .` dan **oldin** frontend qurilgan bo'lishi shart
> (`make frontend`). Aks holda `pattern all:frontend/dist: no matching files
> found` xatosi chiqadi. `make test`/`make vet` UI hali qurilmagan bo'lsa,
> uni o'zi quradi. `reconcli` uchun frontend kerak emas.

---

## Testlar

```sh
make test                        # go test ./...  — hamma paket, ildiz paketi ham
make race                        # go test -race ./...  — race detector bilan
cd frontend && npm run check     # Svelte/TypeScript turlarini tekshirish
```

`make test` endi **barcha** paketlarni, jumladan ildiz paketidagi veb-server va
monitoring testlarini (`monitor_test.go`, `monitor_integration_test.go`)
ishga tushiradi — avval `./internal/...` naqshi ularni jimgina o'tkazib
yuborardi.

Testlar nimani qamraydi (asosiylari): graf ma'lumotlar modelining parallel
o'qish/yozishda xavfsizligi, qamrov qoidalari (MX/NS IP'lari, redirect'lar,
sitemap), nmap'ning IPv4/IPv6 argumentlari, soft-404 kalibrlash, API kalitlari
va tokenlarning xato matnlariga tushmasligi, SQLite'ni ikki jarayon bir vaqtda
ishlatishi, tarixni saqlash/dedup/chegara, monitoringning saqlanishi va
to'liq bo'lmagan skanlarni e'tiborsiz qoldirishi, hisobot formatlari
(SARIF joylashuvlari, `<nil>` yo'qligi).

**CI** (GitHub Actions, `.github/workflows/ci.yml`) har bir push va pull
request'da `go vet ./internal/... ./cmd/...`, `go test -race ./internal/...` va
CLI qurilishini bajaradi. Veb-server paketi `frontend/dist`ni embed qilgani
uchun uni ham CI'da tekshirish uchun workflow'ga frontend qurish
(`npm ci && npm run build`, `npm run check`) va `go vet ./...` /
`go test -race ./...` qadamlarini qo'shish tavsiya etiladi. Lokal `make test`
va `make race` bularni allaqachon bajaradi.

---

## Loyiha tuzilishi

```
osint-forge/
├── main.go                 # veb-server ishga tushishi (bayroqlar, embed, :8081)
├── api.go                  # HTTP marshrutlar: JSON API, eksport, SPA, CSRF qo'riqchisi
├── sse.go                  # Server-Sent Events hub (jonli yangilanishlar)
├── app.go                  # backend: skan boshqaruvi, config, manbalar to'plami
├── app_history.go          # tarix/eslatma yordamchilari
├── app_screenshot.go       # so'rov bo'yicha skrinshot (POST /api/screenshot)
├── monitor.go              # uzluksiz monitoring rejalashtirgichi (+ monitor.json)
├── monitor_filter.go       # monitoring xabar filtri (shablonlar, turlar, jiddiylik)
├── start.sh                # ishga tushirgich (run / dev / build)
├── Makefile                # qurish va test buyruqlari
├── .github/workflows/      # CI
├── cmd/reconcli/           # xuddi shu dvigatel ustidagi CLI
├── internal/
│   ├── config/             # sozlamalarni yuklash/saqlash, standart qiymatlar
│   ├── core/               # pipeline, bosqichlar, collector, nishon, scope
│   ├── graph/              # konkurentlikka chidamli graf + Obsidian eksport
│   ├── recon/              # passiv OSINT manbalari (+ 5000 subdomen ro'yxati)
│   ├── scan/               # aktiv manbalar (+ bidi.go: doimiy Firefox orqali tez skrinshot)
│   │   ├── checks/         #   ichki shablonlar (.json)
│   │   └── wordlists/      #   SecLists fuzzing ro'yxatlari
│   ├── cve/                # NVD moslashtirish, SQLite kesh, KEV + EPSS
│   ├── history/            # skanlarni saqlash, ro'yxat, diff
│   ├── notes/              # pentester teglari va eslatmalari
│   ├── notify/             # Telegram / webhook bildirishnomalari
│   └── report/             # HTML / MD / CSV / SARIF / JSON generatorlari
└── frontend/
    └── src/
        ├── App.svelte      # asosiy qobiq (SSE, resync, ko'rinishlar)
        ├── components/     # DetailPanel, TableView, Gallery, HistoryDrawer,
        │                   # MonitorDrawer, SourcesDrawer, SettingsModal,
        │                   # NotesEditor, NextStep, ShotPreview, Legend, Footer
        └── lib/            # api.ts, graph.ts (Cytoscape), state, guidance, actions, models,
                            # layoutCore.ts + layout.worker.ts (fCoSE, halqalar, ajratish)
```

### Yangi manba qo'shish

Har bir manba `core.Source` interfeysini amalga oshiradi:

```go
type Source interface {
    Name() string                                  // panel va loglardagi nom
    Stage() core.Stage                             // StageDiscovery … StagePost
    Applicable(core.Target) bool                   // kalit/sozlama yo'q bo'lsa false
    Run(ctx context.Context, c *core.Collector) error
}
```

Manba topgan narsalarini `Collector` orqali grafga qo'shadi. Qoidalar:

- Aktiv manba har bir host'ga so'rov yuborishdan oldin `c.InScope(host)` bilan
  qamrovni tekshirishi shart. HTTP so'rovlari uchun kontekstni
  `withScope(ctx, c)` bilan o'rang — shunda redirect'lar ham qamrovdan
  chiqmaydi.
- Host nomini **jonli** DNS orqali resolve qilsangiz, `c.MarkResolved(host, ip)`
  ni chaqiring — IP faqat shunda aktiv skan qamroviga kiradi. Tarixiy
  ma'lumotlar (passiv DNS) uchun buni chaqirmang.
- Tugunni o'qish uchun `c.GetNode` dan foydalaning: u nusxa qaytaradi. Grafning
  jonli tugunini to'g'ridan-to'g'ri o'qish boshqa manba bilan race'ga olib
  keladi.
- Uzoq sikllarda `ctx.Err()` ni tekshiring — "To'xtatish" va vaqt byudjeti shu
  orqali ishlaydi.

Yangi manbani
`app.go` dagi `buildSources` ga **va** `cmd/reconcli/main.go` dagi ro'yxatga
qo'shing — passiv bo'lsa umumiy ro'yxatga, aktiv bo'lsa `consent` / `-active`
blokiga.

---

## Muammolarni hal qilish

| Belgi                                                  | Sabab va yechim                                                     |
| ------------------------------------------------------ | ------------------------------------------------------------------- |
| `listen 127.0.0.1:8081: address already in use`        | Port band (ehtimol boshqa nusxa ishlayapti). Uni to'xtating yoki `-addr 127.0.0.1:8082` bilan ishga tushiring. |
| `a scan is already running`                            | Bir vaqtda bitta skan. Avval joriysini to'xtating (interfeysdagi tugma yoki `POST /api/cancel`) va "To'xtatilmoqda…" tugashini kuting. |
| `noto'g'ri nishon: …`                                  | Nishon formati noto'g'ri — [Nishon formatlari](#nishon-formatlari) ga qarang. |
| Faqat passiv natijalar, port/URL yo'q                  | Ruxsat (consent) belgilanmagan yoki CLI'da `-active` yo'q.          |
| Servis versiyalari va CVE kam                           | `nmap` PATH'da yo'q — sof-Go port skaner ishlagan (`GET /api/nmap` → `false`). nmap'ni o'rnating. |
| CVE moslashtirish sekin                                | NVD kaliti yo'q — so'rovlar limitga mos sekinlashtiriladi. `nvd_key` qo'shing. |
| Skrinshotlar yo'q                                      | Chromium/Firefox PATH'da topilmadi yoki `screenshots` o'chiq.        |
| Skrinshot "sahifa ochilmadi" / "javob bermadi" xatosi bilan | Sayt yopiq, DNS topilmadi yoki 15 soniyada umuman javob bermadi — bu saytning holati, brauzerniki emas. |
| Footer'da uzoq vaqt "🧭 Graf joylashtirilmoqda…"        | Minglab tugunli graf ~20–30 soniyada joylashadi. Bu vaqtda interfeys bilan ishlash mumkin. |
| Monitoring: "o'zgarish bor, lekin filtrga mos emas"    | O'zgarishlar kuzatuv filtridan o'tmadi. Kerak bo'lsa ✏️ bilan filtrni kengaytiring ("Hamma o'zgarishlar"). |
| Panelda "Skrinshot olish" tugmasi chiqdi, rasm yo'q     | Bu sahifaga skan so'rov yubormagan (arxiv/sitemap/JS) yoki skrinshotlar o'chirilgan — rasm faqat tugma bosilganda olinadi. |
| Kalitli manba (Shodan, Censys…) ishlamadi              | Kalit bo'sh bo'lsa manba umuman ro'yxatga kirmaydi. ⚙ da kalitni tekshiring, "Manbalar" panelida holatini ko'ring. |
| Ba'zi hostlar yoki IP'lar aktiv skanlanmadi ("N IP qamrovdan tashqarida") | Ular qamrovdan tashqarida (`scope_strict`): MX/NS serverlari, passiv-DNS IP'lari, begona domenlar. Ruxsatingiz bo'lsa, `extra_scope` ga qo'shing. |
| Skan erta to'xtadi                                     | `scan_timeout_min` byudjeti tugagan. Qiymatni oshiring yoki CLI'da `-timeout` bering. |
| nmap uzoq ishlaydi                                     | `-sV` har bir ochiq portga ko'plab so'rov yuboradi. Sozlamalarda `nmap_args` ni qisqartiring (masalan `-sV -T4 --top-ports 100` yoki `-p 80,443,8080`). |
| Tarixda skanlar kutilganidan kam                       | Oldingisi bilan bir xil skan eski nusxani almashtiradi; nishon boshiga 200 tadan ortig'i o'chiriladi. |
| Monitoring paneli: "skan to'liq tugamadi"              | Monitoring skani to'xtatilgan yoki vaqt byudjetiga sig'magan — u saqlanmadi va taqqoslanmadi. `scan_timeout_min` ni oshiring. |
| Monitoring paneli: "xabar yuborilmadi: …"              | Telegram/webhook rad etdi — sabab xabarning o'zida (masalan "chat not found"). ⚙ dagi token/chat ID ni tekshirib, "✈ Test xabar" bilan sinang. |
| `cross-origin request blocked` (403)                   | API'ga boshqa origin'dan murojaat qilinyapti. Interfeysni server manzilidan oching yoki `curl` kabi `Origin` yubormaydigan mijoz ishlating. |
| `pattern all:frontend/dist: no matching files found`   | Frontend qurilmagan — avval `make frontend`.                         |

---

## Ma'lum cheklovlar va tugallanmagan ishlar

**Cheklovlar:**

- Autentifikatsiya (login) yo'q — dastur faqat lokal foydalanish uchun
  mo'ljallangan.
- Bir vaqtda faqat bitta skan ishlaydi; monitoring skanlari ham shu navbatda.
- Monitoring skani ekrandagi grafni almashtiradi (alohida "fon" grafi yo'q).
- "To'xtatish" ishlab turgan so'rovlarni bekor qiladi, lekin zone transfer
  (AXFR) kabi ba'zi tarmoq amallari o'z timeout'i (≈10 s) tugashini kutadi.

**Kodda boshlangan, lekin hali tugallanmagan:**

- **Bulut bucket tekshiruvlari** — graf modelida `bucket` tuguni (S3/GCS/Azure)
  va Post bosqichida "bucket checks" ko'zda tutilgan, lekin hozircha hech bir
  manba bunday tugun yaratmaydi.
- **Loyiha (project) rejimi** — ichki `ScanRequest` tuzilmasida `project` va
  skan boshiga qo'shimcha `extraScope` maydonlari bor, lekin `POST /api/scan`
  hozircha faqat `target` va `consent` ni qabul qiladi. Hozir qo'shimcha
  qamrovni faqat umumiy `extra_scope` sozlamasi orqali berish mumkin.
- **CLI / DevOps rejimi** — `reconcli` kelgusidagi to'liq CLI/DevOps rejimining
  asosi sifatida yaratilgan; hozircha u bitta nishonni skanlab, hisobot
  yozadi.

---

## Litsenziya va mas'uliyat

[MIT litsenziyasi](LICENSE) asosida tarqatiladi.

osint-forge **avtorizatsiyalangan xavfsizlik testi va ta'lim** uchun
mo'ljallangan. Uni faqat o'zingizga tegishli yoki tekshirishga **yozma ruxsat**
berilgan tizimlarga qarshi ishlating. Ruxsatsiz skanlash ko'p yurisdiksiyada
qonunga ziddir. Dastur mualliflari uni noto'g'ri ishlatishdan kelib chiqadigan
oqibatlar uchun javobgar emas.
