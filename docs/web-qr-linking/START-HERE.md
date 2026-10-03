# Web QR linking: run the whole project (BE-6.1)

One project. Three parts:

| Folder | What it is |
|---|---|
| `apps/backend` | The backend (with the Supabase pooler TLS fix in `src/db/pool.ts`) |
| `apps/mobile` | The Sealine phone app (Settings → Scan QR Code now links Web) |
| `sealine-web-mervin-style` | The Web app with the QR page (its own pnpm workspace) |

`apps/web` is the repo's older web app and is **not** used here.

## One-time setup
1. Unzip, then in PowerShell: `cd INFRA_backend` and `pnpm install`.
2. Copy **your own** `apps\backend\.env` into this project. It is NOT in the zip. In it set `CORS_ORIGIN=http://localhost:3000`.
3. `cd sealine-web-mervin-style` and `pnpm install` (this part has its own lockfile).

## Every time (4 PowerShell windows)
```powershell
# 1 Backend
cd INFRA_backend\apps\backend
pnpm dev                                   # wait for: listening on :4000

# 2 Tunnel
cloudflared tunnel --url http://localhost:4000     # copy the https://....trycloudflare.com address

# 3 Web  (open http://localhost:3000)
cd sealine-web-mervin-style
$env:API_BASE_URL="https://YOUR-TUNNEL-ADDRESS"
pnpm --filter "@wpt/web" dev

# 4 Phone app (plug the phone in by USB, press a)
cd apps\mobile
Set-Content .env "EXPO_PUBLIC_BACKEND_URL=https://YOUR-TUNNEL-ADDRESS"
npx expo start -c --tunnel
```
Then on the phone: log in, **Settings → Scan QR Code**, scan the Web QR, tap **Link this account**.
The address must be identical in steps 3 and 4. A new tunnel window means a new address: redo 3 and 4.

## Known issues (not caused by this work)
- `apps/backend/scripts/verify_all.sql` and `verify_all_summary.sql` have unresolved git conflict markers committed (commit 8d39b32). They are check scripts only, not runtime code.
- `phone-entry.tsx` has 4 existing TypeScript errors (gradient typing).
- Web tokens are kept in browser localStorage; the Web build never refreshes tokens (stale after ~1 hour).
- `DATABASE_CA_CERT` in `pool.ts` is ignored when `sslmode` is in the URL (existing bug).
