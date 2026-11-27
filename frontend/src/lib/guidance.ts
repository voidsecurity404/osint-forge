// "Keyingi qadam" — teaching mode. For a node it answers: nega muhim, qo'lda
// nimani TEKSHIRISH kerak, qaysi vositalar bilan. Matn o'zbekcha. Mazmun
// avtorizatsiyalangan test uchun: zaiflikni ANIQLASH/TASDIQLASH yo'nalishida,
// bosqichma-bosqich ekspluatatsiya ko'rsatmasi emas.
import type { graph } from "./models";
import { statusOf } from "./graph";

export interface Guide {
  title: string;
  why: string;
  checks: string[]; // qo'lda tekshirish punktlari
  tools?: string[];
}

const SCOPE = "Faqat yozma ruxsat (scope) ichidagi nishonda.";

// Port → nega internetga ochiq bo'lmasligi kerak + tekshirish punktlari.
const PORTS: Record<string, Guide> = {
  "21": { title: "FTP (21)", why: "Ko'pincha anonim kirish yoqilgan va trafik shifrlanmagan.", checks: ["Anonim kirish yoqilganmi?", "Banner versiyasi ma'lum zaiflikka tegishlimi (CVE paneli)."], tools: ["nmap --script ftp-anon", "searchsploit"] },
  "22": { title: "SSH (22)", why: "Masofaviy kirish nuqtasi; eski versiya yoki zaif sozlama xavf tug'diradi.", checks: ["Versiya va qo'llab-quvvatlanadigan algoritmlar zamonaviymi?", "Parol bilan kirish yoqilganmi yoki faqat kalitmi?"], tools: ["ssh-audit", "nmap --script ssh2-enum-algos"] },
  "23": { title: "Telnet (23)", why: "Trafik to'liq shifrlanmagan — zamonaviy tarmoqda bo'lmasligi kerak.", checks: ["Nega SSH o'rniga Telnet ishlatilyapti?", "Qurilma turi va versiyasi."], tools: ["nmap --script telnet-ntlm-info"] },
  "25": { title: "SMTP (25)", why: "Noto'g'ri sozlanganda open relay yoki foydalanuvchi nomlarini oshkor qilishi mumkin.", checks: ["Open relay sinovi.", "VRFY/EXPN buyruqlari o'chirilganmi?", "STARTTLS mavjudmi?"], tools: ["nmap --script smtp-open-relay,smtp-commands", "swaks"] },
  "53": { title: "DNS (53)", why: "Zone transfer (AXFR) ochiq bo'lsa, butun ichki xarita oshkor bo'ladi.", checks: ["AXFR ruxsat etilganmi? (bu dastur avtomatik sinaydi)", "Recursion tashqaridan ochiqmi?"], tools: ["dig", "dnsrecon"] },
  "139": { title: "SMB (139)", why: "Eski SMBv1 va anonim kirish xavfli.", checks: ["Null session ruxsat etilganmi?", "SMBv1 o'chirilganmi?"], tools: ["enum4linux-ng", "nmap --script smb-protocols"] },
  "445": { title: "SMB (445)", why: "Windows tarmoqlarida tez-tez noto'g'ri sozlanadi (ochiq share, imzolamaslik).", checks: ["SMB signing majburiymi?", "Guest/null orqali share'lar ko'rinadimi?", "Versiya ma'lum zaiflikka tegishlimi."], tools: ["nmap --script smb-protocols,smb2-security-mode", "enum4linux-ng"] },
  "1433": { title: "MS SQL (1433)", why: "Ma'lumotlar bazasi internetga ochiq bo'lmasligi kerak.", checks: ["Baza nega tashqaridan ko'rinyapti?", "Versiya va shifrlash."], tools: ["nmap --script ms-sql-info"] },
  "3306": { title: "MySQL (3306)", why: "Baza internetga ochiq — noto'g'ri sozlama.", checks: ["Nega tashqaridan ulanish mumkin?", "Versiya va auth plagini."], tools: ["nmap --script mysql-info"] },
  "3389": { title: "RDP (3389)", why: "Parol hujumlari va ma'lum kritik zaifliklar nishoni.", checks: ["NLA (Network Level Authentication) yoqilganmi?", "Versiya ma'lum zaiflikka tegishlimi (CVE paneli)."], tools: ["nmap --script rdp-ntlm-info,rdp-enum-encryption"] },
  "5432": { title: "PostgreSQL (5432)", why: "Baza internetga ochiq bo'lmasligi kerak.", checks: ["Nega tashqaridan ko'rinadi?", "Versiya."], tools: ["nmap --script pgsql-brute"] },
  "6379": { title: "Redis (6379)", why: "Odatda autentifikatsiyasiz keladi — ma'lumot oshkor bo'lishi mumkin.", checks: ["Auth talab qilinadimi?", "Internetga nega ochiq?"], tools: ["nmap --script redis-info"] },
  "9200": { title: "Elasticsearch (9200)", why: "Ko'pincha auth'siz — indeks ma'lumotlari oshkor bo'ladi.", checks: ["Auth yoqilganmi?", "Ma'lumotni yuklab olmang — faqat mavjudligini qayd eting."], tools: ["curl"] },
  "27017": { title: "MongoDB (27017)", why: "Eski sozlamada auth o'chiq bo'lishi mumkin.", checks: ["Auth yoqilganmi?", "Internetga nega ochiq?"], tools: ["nmap --script mongodb-info"] },
};

const WEB_PORT: Guide = {
  title: "Web servis",
  why: "Web ilovalar eng katta hujum yuzasi: yashirin yo'llar, eski komponentlar, auth xatolari.",
  checks: ["Texnologiya va versiyani aniqlang (eski komponent CVE paneliga tushadi).", "robots.txt, sitemap, /.git/, /.env, admin panellarini tekshiring.", "Trafikni Burp orqali ko'rib, parametrlarni belgilang."],
  tools: ["Burp Suite", "nuclei", "whatweb"],
};

function statusGuide(code: number): Guide | null {
  if (code === 401 || code === 403) {
    return {
      title: `${code} — kirish cheklangan`,
      why: "Himoyalangan resurs mavjudligini bildiradi. Kirish mantig'i to'g'ri sozlanganini tekshirish kerak.",
      checks: ["Qanday auth turi ishlatilmoqda (Basic, token, form)?", "Resurs boshqa yo'l orqali ham ochiladimi?", "Xato sahifasi ortiqcha ma'lumot (versiya, stack) oshkor qiladimi?"],
      tools: ["Burp Suite"],
    };
  }
  if (code >= 500) {
    return {
      title: `${code} — server xatosi`,
      why: "Server ichki xatosi ko'pincha noto'g'ri ishlov berilgan kirish belgisidir; xato xabari ma'lumot oshkor qilishi mumkin.",
      checks: ["Javobda stack trace, yo'l yoki versiya ko'rinadimi?", "Qaysi so'rov bu xatoni keltirib chiqardi — qayd eting."],
      tools: ["Burp Suite"],
    };
  }
  if (code >= 300 && code < 400) {
    return {
      title: `${code} — yo'naltirish`,
      why: "Redirect manzili boshqa yo'l yoki hostni oshkor qilishi mumkin.",
      checks: ["`location` qayerga ishora qiladi?", "Yo'naltirish foydalanuvchi kiritgan qiymatga bog'liqmi (open redirect)?"],
    };
  }
  return null;
}

const FINDING: Record<string, Guide> = {
  "git-exposed": { title: ".git papkasi ochiq", why: "Ochiq .git butun manba kodini va tarixini (ba'zan sirlarni) tiklashga imkon beradi.", checks: ["Kodni tiklab, ichida sir/parol bor-yo'qligini tekshiring.", "Commit tarixida o'chirilgan maxfiy ma'lumotni qidiring."], tools: ["git-dumper", "trufflehog"] },
  "env-exposed": { title: ".env fayli ochiq", why: ".env odatda baza parollari, API kalitlari va maxfiylarni saqlaydi.", checks: ["Qaysi kalitlar oshkor bo'ldi?", "Topilgan sirlar amaldaligini (ruxsat bilan) baholang va tezda aylantirishni tavsiya eting."], tools: ["curl"] },
  "cors": { title: "CORS noto'g'ri sozlangan", why: "Juda ochiq CORS boshqa sayt foydalanuvchi ma'lumotini o'qishiga yo'l qo'yishi mumkin.", checks: ["`Access-Control-Allow-Origin` ixtiyoriy Origin'ni aks ettiradimi?", "`Allow-Credentials: true` bilan birga kelganmi?"], tools: ["curl", "Burp Suite"] },
  "dirlisting": { title: "Katalog ro'yxati ochiq", why: "Server papka ichidagi fayllar ro'yxatini ko'rsatmoqda — zaxira, log yoki maxfiy fayllar chiqishi mumkin.", checks: ["Papkada maxfiy fayl (zaxira, .bak, log) bormi?"] },
  "takeover": { title: "Subdomain takeover ehtimoli", why: "Egasiz tashqi resursga ishora qiluvchi subdomen o'zlashtirilib, saytingiz nomidan foydalanilishi mumkin.", checks: ["CNAME qaysi xizmatga ishora qiladi?", "O'sha resurs haqiqatan egasizmi (xizmat hujjatiga ko'ra tasdiqlang)."] },
  "weak-tls": { title: "Eski TLS protokoli", why: "TLS 1.0/1.1 zamonaviy hisoblanmaydi va o'chirilishi kerak.", checks: ["Qaysi protokol/shifrlar yoqilgan?", "TLS 1.2+ ga o'tkazishni tavsiya eting."], tools: ["testssl.sh", "sslscan"] },
  "cert-expired": { title: "Sertifikat muddati o'tgan", why: "Muddati o'tgan sertifikat foydalanuvchilarga ogohlantirish beradi va xizmat ishonchini pasaytiradi.", checks: ["Qachon tugagan?", "Yangilashni tavsiya eting."] },
  "spf-missing": { title: "SPF yozuvi yo'q", why: "SPF bo'lmasa, domen nomidan soxta xat (spoofing) yuborish osonlashadi.", checks: ["DNS'ga to'g'ri SPF yozuvi qo'shishni tavsiya eting."] },
  "dmarc-missing": { title: "DMARC yozuvi yo'q", why: "DMARC email autentifikatsiyasini kuchaytiradi va spoofing'ni cheklaydi.", checks: ["DMARC siyosatini qo'shishni tavsiya eting."] },
  "hibp": { title: "Email buzilgan bazalarda", why: "Oshkor bo'lgan email parol qayta ishlatilsa hisob egalanishi mumkin.", checks: ["Xodimlarga parol almashtirish va 2FA ni tavsiya eting."] },
  "github": { title: "Domen GitHub kodida eslatilgan", why: "Ommaviy repozitoriylardagi config/skriptlarda ichki hostlar, kalit yoki parollar sizib chiqqan bo'lishi mumkin.", checks: ["Ko'rsatilgan repo va fayllarni ko'rib chiqing: sir, ichki manzil bormi?", "Topilgan kalit amaldaligini (ruxsat bilan) baholang va aylantirishni tavsiya eting."], tools: ["trufflehog", "gitleaks"] },
  "cert-expiring": { title: "Sertifikat tez tugaydi", why: "Yangilanmasa, yaqin kunlarda foydalanuvchilar xavfsizlik ogohlantirishini ko'radi.", checks: ["Tugash sanasi va avtomatik yangilanish (ACME/certbot) sozlanganmi?"] },
  "spf-weak": { title: "SPF juda ochiq (+all)", why: "'+all' har qanday serverga domen nomidan xat yuborishga ruxsat beradi — SPF amalda o'chiq.", checks: ["SPF'ni '-all' yoki '~all' bilan tugatishni tavsiya eting."], tools: ["dig TXT"] },
  "dmarc-none": { title: "DMARC p=none", why: "Kuzatuv rejimi: soxta xatlar haqida hisobot keladi, lekin ular bloklanmaydi.", checks: ["Hisobotlarni tahlil qilib, p=quarantine yoki p=reject ga o'tishni tavsiya eting."] },
  "axfr": { title: "Zone transfer (AXFR) ochiq", why: "Name server butun DNS zonasini istalgan kishiga beradi — barcha ichki host nomlari oshkor.", checks: ["Qaysi name server(lar) javob berdi?", "AXFR'ni faqat ishonchli ikkilamchi serverlarga cheklashni tavsiya eting."], tools: ["dig AXFR"] },
  "http-methods": { title: "Xavfli HTTP metodlar", why: "PUT/DELETE/TRACE kabi metodlar noto'g'ri sozlanganda fayl yozish yoki XST'ga yo'l ochadi.", checks: ["Allow sarlavhasi haqiqatan ishlaydimi yoki faqat e'lon qilinganmi (ruxsat bilan sinang)?", "Keraksiz metodlarni o'chirishni tavsiya eting."], tools: ["curl -X OPTIONS -i"] },
  "js-secret": { title: "JavaScript'da sir", why: "Brauzerga yuboriladigan JS'dagi kalitni istalgan tashrif buyuruvchi o'qiy oladi.", checks: ["Kalit amaldami va qanday huquqlarga ega (ruxsat bilan baholang)?", "Kalitni aylantirib, backend'ga ko'chirishni tavsiya eting."], tools: ["trufflehog"] },
  "check": { title: "Oshkor resurs (ichki shablon)", why: "Admin panel, debug endpoint yoki zaxira fayl internetdan ochiq ko'rinmoqda.", checks: ["Sahifani ochib, haqiqatan oshkor ekanini tasdiqlang (yolg'on ijobiyni istisno eting).", "Kirish cheklovi qo'yish yoki o'chirishni tavsiya eting."], tools: ["curl", "Burp Suite"] },
  "nuclei": { title: "Nuclei topilmasi", why: "ProjectDiscovery shabloni mos keldi — tafsilot shablon ID'sida.", checks: ["Shablon ID bo'yicha hujjatni o'qing va natijani qo'lda tasdiqlang."], tools: ["nuclei -id <template> -u <url>"] },
};

const NODE_TYPE: Record<string, Guide> = {
  param: { title: "URL parametri", why: "Foydalanuvchi kiritadigan parametrlar in'ektsiya va mantiq xatolarining asosiy kirish nuqtasi.", checks: ["Nomi qaysi sinovga ishora qiladi (panelda ko'rsatilgan)?", "Qiymatni Burp'da o'zgartirib, javob farqini kuzating.", "SQLi/XSS/redirect uchun qo'lda sinang (faqat scope ichida)."], tools: ["Burp Suite", "sqlmap", "ffuf"] },
  bucket: { title: "Bulut bucket", why: "Ochiq S3/GCS/Azure bucket maxfiy fayllarni oshkor qilishi yoki yozishga ruxsat berishi mumkin.", checks: ["Ro'yxat (listing) ochiqmi?", "Yozish huquqi bormi (ruxsat bilan)?"], tools: ["aws s3 ls", "gsutil"] },
  email: { title: "Email manzil", why: "Ijtimoiy injiniring va buzilgan baza tekshiruvi uchun foydali.", checks: ["Buzilgan bazalarda bormi (HIBP)?", "Qaysi xodim/rolga tegishli?"] },
  cve: { title: "Ma'lum zaiflik (CVE)", why: "Aniqlangan versiyaga mos keluvchi ommaviy zaiflik.", checks: ["Versiya haqiqatan mosmi (yolg'on ijobiyni istisno eting)?", "KEV/EPSS bo'yicha ustuvorlikni baholang.", "Rasmiy yangilanish/patch mavjudmi."], tools: ["searchsploit", "nuclei"] },
  certificate: { title: "TLS sertifikat", why: "SAN maydonidagi domenlar yangi ichki hostlarni oshkor qilishi mumkin.", checks: ["SAN'da yangi subdomenlar bormi?", "Muddati va chiqaruvchisi."] },
  asn: { title: "ASN (tarmoq)", why: "Bir ASN ostidagi IP bloklari odatda bitta tashkilotniki — qamrovni kengaytiradi.", checks: ["Bu ASN'dagi boshqa IP bloklari ham scope ichidami?"] },
};

export function guideFor(n: graph.Node): Guide | null {
  if (!n) return null;
  if (n.type === "port") {
    const port = String(n.props?.port ?? n.label).split("/")[0];
    const svc = String(n.props?.service ?? "").toLowerCase();
    if (PORTS[port]) return PORTS[port];
    if (svc.includes("http")) return WEB_PORT;
    return null;
  }
  if (n.type === "url") {
    const code = statusOf(n);
    if (code) return statusGuide(code);
    return null;
  }
  if (n.type === "finding") {
    const id = n.id.replace(/^finding:/, "");
    for (const key of Object.keys(FINDING)) if (id.startsWith(key)) return FINDING[key];
    return null;
  }
  return NODE_TYPE[n.type] ?? null;
}

export { SCOPE };
