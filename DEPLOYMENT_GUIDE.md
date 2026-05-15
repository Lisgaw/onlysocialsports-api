# Sports Partner API — Vercel Deployment Rehberi

## Ön Koşullar
1. **Supabase hesabı** oluştur → [supabase.com](https://supabase.com)
2. **Vercel hesabı** oluştur → [vercel.com](https://vercel.com)
3. GitHub reposu Vercel'e bağlanmalı

---

## Adım 1: Supabase Kurulumu

### 1.1 Yeni Proje Oluştur
- Supabase Dashboard → "New Project"
- Region: **EU West (Frankfurt)** (Türkiye'ye en yakın)
- Database password: güçlü bir şifre seç ve kaydet

### 1.2 SQL Migration Çalıştır
- Dashboard → SQL Editor → "New Query"
- `backend/db/migrations/001_initial_schema.sql` dosyasının içeriğini yapıştır
- "Run" tıkla → 28 tablo + indexler + seed data oluşur

### 1.3 API Anahtarlarını Al
- Dashboard → Settings → API
- **Project URL:** `https://xxxxx.supabase.co`
- **service_role key:** `eyJhbGciOiJ...` (gizli tut!)

---

## Adım 2: Vercel Deployment

### 2.1 GitHub'dan Import
1. [vercel.com/new](https://vercel.com/new) → GitHub repo seç
2. **Root Directory:** `backend` olarak ayarla
3. **Framework Preset:** "Other"
4. **Build Command:** `npm install`
5. **Output Directory:** `.`

### 2.2 Environment Variables
Vercel Dashboard → Settings → Environment Variables:

| Key | Value | Ortam |
|-----|-------|-------|
| `SUPABASE_URL` | `https://xxxxx.supabase.co` | Production |
| `SUPABASE_SERVICE_KEY` | `eyJhbGciOiJ...` | Production |
| `JWT_SECRET` | Rastgele 64 karakter string | Production |
| `NODE_ENV` | `production` | Production |

### 2.3 Deploy
- Push to `main` branch → otomatik deploy tetiklenir
- Veya Vercel Dashboard'dan "Deploy" tıkla

---

## Adım 3: Flutter Uygulamasını Güncelle

API URL'sini güncelle:
```dart
// lib/core/constants/api_constants.dart
static const String baseUrl = 'https://your-project.vercel.app';
```

---

## Mimari Notlar

### ⚠️ Vercel Serverless Limitleri
- **Execution timeout:** 30 saniye (Hobby), 300 saniye (Pro)
- **Body size:** 4.5MB
- **Concurrent:** 1000 (Hobby), 100K (Pro)
- **WebSocket:** Desteklenmiyor → Supabase Realtime kullan
- **File system:** Read-only → JSON persistence çalışmaz

### 🔄 Migration Durumu
Şu an backend **in-memory store** kullanıyor. Vercel'de çalışması için:
1. `server.js` → `supabase.js` client'ı kullanacak şekilde migrate et
2. Tüm `store.xxx.find()` → `supabase.findOne()` / `supabase.query()`
3. Tüm `store.xxx.push()` → `supabase.insert()`
4. WebSocket → Supabase Realtime channels

### 📁 Dosya Yapısı
```
backend/
├── api/
│   └── index.js          ← Vercel serverless entry point
├── db/
│   ├── migrations/
│   │   └── 001_initial_schema.sql  ← PostgreSQL schema
│   ├── store.js           ← In-memory store (geçici)
│   ├── supabase.js        ← Supabase client adapter
│   └── persistence.js     ← JSON persistence (Docker only)
├── middleware/
│   ├── auth.js
│   └── content-filter.js
├── routes/
│   └── admin.js
├── server.js              ← Ana sunucu (Docker mode)
├── vercel.json            ← Vercel yapılandırması
├── package.json
├── .env.example
└── Dockerfile
```

---

## Hızlı Deployment Akışı (Özet)

```bash
# 1. Supabase'de SQL çalıştır
# 2. Vercel'e import et (root: backend/)
# 3. Env vars ayarla
# 4. git push → otomatik deploy
# 5. Flutter'da API URL güncelle
```
