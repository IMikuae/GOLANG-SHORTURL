# Yue Short (Go) — URL Shortener

Port Go 1:1 dari `NEXTJS-SHORTURL` (Next.js 16 + SQLite). Perilaku API, skema
database, pesan error (Indonesia), rate limit, routing host, dan verifikasi DNS
disamakan dengan versi Next.js. Frontend disajikan server-side (Go templates +
vanilla JS) dengan alur yang sama: landing + shortener, login/register,
gerbang password, expired, dashboard (overview, tautan, analitik, QR, API,
pengaturan).

## Menjalankan

```bash
go run .                 # http://localhost:3000
go build -o shorturl .   # binary tunggal (SQLite pure-Go, tanpa CGO)
```

DB SQLite dibuat otomatis di `./data/shorturl.db` (WAL). DB lama versi Next.js
bisa langsung dipakai — migrasi ringan (`table_info` + `ALTER TABLE`) sama
seperti `src/lib/db.js`.

## Environment (semua opsional, sama seperti Next.js)

```bash
PORT=3000
DATA_DIR=./data
NEXT_PUBLIC_APP_URL=http://localhost:3000  # origin absolut + target CNAME
APP_DOMAIN=app.contoh.com                  # aktifkan strict host routing
GEO_COUNTRY_HEADER=x-geo-country            # header negara kustom
TRUST_PROXY=1                               # "0" = abaikan header proxy
COOKIE_SECURE=0                             # "1" selalu secure, "0" non-secure
DNS_RESOLVER=1.1.1.1,8.8.8.8                # kosong = resolver sistem
LOG_LEVEL=info                              # debug | info | warn | error
```

## Struktur

```
main.go                  entrypoint, env, graceful shutdown
go.mod                   module shorturl (modernc.org/sqlite + x/crypto)
internal/
  db/db.go               skema SQLite + semua query (port lib/db.js)
  auth/auth.go           scrypt N=16384 r=8 p=1 keyLen 64, sesi 30 hari, API key
  validate/validate.go   URL + anti-SSRF + alias + hostname (port lib/validate.js)
  geo/geo.go             negara/IP/prefix/device (port lib/geo.js)
  hosts/hosts.go         normalisasi host + strict routing (port lib/hosts.js)
  dns/dns.go             verifikasi TXT/CNAME + timeout 5 dtk (port lib/dns.js)
  ratelimit/ratelimit.go fixed-window in-memory + LIMITS (port lib/rate-limit.js)
  meta/meta.go           analyticsMeta + appOrigin (port lib/request-meta.js + origin.js)
  logger/logger.go       log terstruktur + redact (port lib/logger.js)
  server/
    server.go            router + POST /api/shorten + GET /{code} + POST /api/unlock
    api_auth.go          register/login/logout + account + password + api-key
    api_links.go         GET/POST /api/links + GET/DELETE /api/links/{id}
    api_domains.go       GET/POST /api/domains + DELETE + POST verify
    pages.go             halaman HTML (index/login/register/pw/expired/dashboard/*)
    helpers.go           pembantu template
web/
  embed.go               //go:embed templates static
  templates/*.html       12 halaman + partial layout/linkrow (port src/app/*)
  static/style.css       token + glass/hero/animasi (port globals.css non-Tailwind)
  static/icons.svg       51 ikon Heroicons v2.2.0 sebagai sprite (outline+solid)
  static/app.js          toast+confirm + util (port ToastProvider)
```

## UI (port visual Next.js)

Semua halaman meniru markup + class Tailwind versi Next.js 1:1:

- Landing: navbar pill, latar angkasa (bintang/planet/pegunungan SVG), hero,
  form shortener + 5 panel quick-option, kartu hasil + QR, stats bar, grid
  8 fitur, demo statistik + area chart, CTA, footer. Validasi client mirror
  server, copy/share/QR toggle.
- Login/register/pw/expired/404: kartu glass + glow ambient + error state +
  checklist password live (register) + hidden-field fallback (pw).
- Dashboard: shell (sidebar + drawer + bottom-nav + logout), metrik,
  LinkRow (copy/open/edit/hapus + badge domain/gembok/expiry, table desktop +
  kartu mobile), analitik (chart SVG multiline + tooltip crosshair + legend
  toggle + distribusi + tabel WCAG), QR grid, ApiKeyCard (mask/show/regenerasi),
  pengaturan (nama, password + strength, DomainManager + DNS rows, notifikasi,
  danger zone ketik-email).

Utilitas Tailwind disediakan lewat CDN browser (`@tailwindcss/browser@4`) +
token `@theme` yang sama; ikon via sprite lokal. Butuh internet saat runtime
(sama seperti QR `api.qrserver.com` dan font Inter Google Fonts).

## API (sama persis dengan Next.js)

| Endpoint | Keterangan |
|---|---|
| `POST /api/shorten` | `{url, alias?, password?, expiresAt?, domainId?}` → `201 {shortUrl, shortCode, domainId}` |
| `POST /api/unlock` | `{code, password, host?}` → `{ok, redirect}` (429 3 lapis, 401 salah, 410 kedaluwarsa) |
| `GET /api/links` | daftar milik user + `totalLinks` + `hostRouting` |
| `POST /api/links` | `{id, url}` ubah tujuan |
| `GET /api/links/{id}` | detail + `analytics{daily, devices, countries, referrers, topCountry, totalTracked}` |
| `DELETE /api/links/{id}` | hapus |
| `POST /api/auth/register` | `{email, password, name?}` → `201 {ok}` + cookie |
| `POST /api/auth/login` | `{email, password}` → `{ok}` + cookie (pesan generik 401) |
| `POST /api/auth/logout` | hapus sesi + cookie |
| `GET /api/account` | profil + apiKey + linkCount |
| `PATCH /api/account` | `{name}` 2–60 char |
| `DELETE /api/account` | `{password}` → `{ok, linksDeleted}` |
| `POST /api/account/password` | `{currentPassword, newPassword}` + cabut sesi lain |
| `POST /api/account/api-key` | regenerasi → `{ok, apiKey}` |
| `GET/POST /api/domains` | daftar + tambah (10/jam/user) |
| `POST /api/domains/{id}/verify` | cek DNS (1/5 dtk/domain) |
| `DELETE /api/domains/{id}` | lepas (tautan di-unlink, tidak dihapus) |
| `GET /{code}` | redirect 302 (host-aware, `/expired` bila kedaluwarsa, `/pw` bila berpassword) |
| `GET /README.md` | README sebagai text/plain |

Contoh:

```bash
curl -X POST http://localhost:3000/api/shorten -H "Content-Type: application/json" -d '{"url":"https://example.com","alias":"docs"}'
curl -X POST http://localhost:3000/api/shorten -H "Content-Type: application/json" -H "Authorization: Bearer ys_live_..." -d '{"url":"https://example.com","domainId":3}'
```

## Catatan port

- Hash password: scrypt `saltHex:hashHex` (salt 16 byte, keyLen 64) — format sama,
  parameter disamakan dengan default Node (`N=16384, r=8, p=1`).
- Short code: alfabet Next.js `23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ`, 7 char.
- Alias global unik (tidak per-domain), reserved list sama (plus `favicon.ico` dkk).
- Rate limit in-memory hilang saat restart, tidak dibagi antar proses (sama seperti Next.js).
- QR tetap via `api.qrserver.com` — tanpa dependency.
- IP penuh tidak pernah disimpan (hanya prefix `/24` / `/64`).
