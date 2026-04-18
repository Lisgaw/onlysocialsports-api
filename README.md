# OnlySocialSports API — Backend

Bu klasör mevcut `backend/` klasörünün kopyasıdır.
Yeni Supabase projesi için env vars güncellendi.

## Deploy Edilecek Proje
- **Vercel Hesabı**: yusuf.kucukugurlu@gmail.com
- **GitHub Repo**: Lisgaw/onlysocialsports-api
- **Vercel URL**: https://onlysocialsports-api.vercel.app

## Env Variables (Vercel Dashboard'a girilecek)

| Key | Value |
|-----|-------|
| `SUPABASE_URL` | https://[YENİ_SUPABASE_ID].supabase.co |
| `SUPABASE_SERVICE_KEY` | [service_role_key — Supabase Dashboard'dan al] |
| `SUPABASE_ANON_KEY` | [anon_key — Supabase Dashboard'dan al] |
| `JWT_SECRET` | [min 32 karakter rastgele string] |
| `NODE_ENV` | production |

## Deployment Adımları

```bash
# 1. Bu klasörü GitHub'a yükle
cd onlysocialsports-api
git init
git remote add origin https://github.com/Lisgaw/onlysocialsports-api.git
git add .
git commit -m "feat: initial backend deployment"
git push -u origin main

# 2. Vercel'de yeni proje oluştur
#    - vercel.com → New Project → GitHub → Lisgaw/onlysocialsports-api
#    - Root Directory: ./
#    - Framework: Other
#    - Env vars ekle (yukarıdaki tablo)
#    - Deploy!
```

## Supabase SQL Migration

Yeni Supabase projesinde SQL Editor'e git ve çalıştır:
- `backend/db/migrations/001_initial_schema.sql`


