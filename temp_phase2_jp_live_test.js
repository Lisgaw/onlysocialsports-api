const fs = require('fs');

const base = 'https://api.onlysocialsport.com/api';

function j(v) { return JSON.stringify(v); }

async function req(method, path, token, body) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : j(body),
  });
  const txt = await r.text();
  let data = null;
  try { data = txt ? JSON.parse(txt) : null; }
  catch { data = { raw: txt }; }
  return { ok: r.ok, status: r.status, data };
}

function hasJapaneseChars(value) {
  return /[\u3040-\u30ff\u3400-\u9fff]/.test(String(value || ''));
}

function isHumanPhotoAvatar(url) {
  const u = String(url || '').toLowerCase();
  return u.includes('randomuser.me') || u.includes('/portraits/');
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  const out = {
    phase: 'phase-2-live-jp-ecosystem-validation',
    baseUrl: base,
    checks: [],
    cleanup: [],
  };

  let adminToken = null;
  let ecosystemId = null;
  const slug = Math.random().toString(36).replace(/[^a-z]/g, '').slice(0, 6) || 'qatest';
  const cityId = `jp_${slug}`;
  const cityName = `Tokyo ${slug}`;

  try {
    const login = await req('POST', '/auth/login', null, {
      email: 'admin@sporpartner.com',
      password: 'Admin123456!',
    });
    out.checks.push({ step: 'admin-login', ...login });
    if (!login.ok) throw new Error('admin login failed');
    adminToken = login.data.accessToken;

    const createEco = await req('POST', '/admin/ecosystems', adminToken, {
      scope: 'CITY',
      countryCode: 'JP',
      cityId,
      cityName,
      sportIds: ['table_tennis'],
      listingType: 'PARTNER',
      botsPerCity: 4,
      maxParticipants: 4,
      hourlyApplications: 1,
    });
    out.checks.push({ step: 'create-jp-ecosystem', ...createEco });
    if (!createEco.ok) throw new Error('ecosystem create failed');

    ecosystemId = createEco.data?.data?.ecosystemIds?.[0] || null;

    let usersResp = null;
    let listingsResp = null;
    for (let i = 0; i < 4; i++) {
      usersResp = await req('GET', '/admin/users?limit=120', adminToken, undefined);
      listingsResp = await req('GET', '/admin/listings?limit=120', adminToken, undefined);

      const bots = (usersResp.data?.data || []).filter(
        (u) => u.isBot === true && u.countryCode === 'JP' && u.city === cityName
      );
      const botIds = new Set(bots.map((b) => b.id));
      const listings = (listingsResp.data?.data || []).filter(
        (l) => l.cityName === cityName && botIds.has(l.userId)
      );

      if (bots.length >= 1 && listings.length >= 1) {
        break;
      }
      await sleep(2000);
    }

    out.checks.push({ step: 'admin-users-fetch', ...usersResp });
    out.checks.push({ step: 'admin-listings-fetch', ...listingsResp });

    const bots = (usersResp?.data?.data || []).filter(
      (u) => u.isBot === true && u.countryCode === 'JP' && u.city === cityName
    );
    const botIds = new Set(bots.map((b) => b.id));
    const listings = (listingsResp?.data?.data || []).filter(
      (l) => l.cityName === cityName && botIds.has(l.userId)
    );

    const avatarSamples = bots.slice(0, 5).map((b) => ({ id: b.id, avatarUrl: b.avatarUrl }));
    const sportSamples = listings.slice(0, 5).map((l) => ({ id: l.id, sportId: l.sportId, sportName: l.sportName }));

    const humanAvatarPass = avatarSamples.length > 0 && avatarSamples.every((s) => isHumanPhotoAvatar(s.avatarUrl));
    const japaneseSportNamePass = sportSamples.length > 0 && sportSamples.every((s) => hasJapaneseChars(s.sportName));

    out.summary = {
      ecosystemId,
      cityId,
      cityName,
      foundBots: bots.length,
      foundListings: listings.length,
      avatarSamples,
      sportSamples,
      checks: {
        humanAvatarPass,
        japaneseSportNamePass,
      },
    };
  } catch (e) {
    out.error = String(e?.message || e);
  } finally {
    if (ecosystemId && adminToken) {
      const del = await req('DELETE', `/admin/ecosystems/${ecosystemId}`, adminToken, undefined);
      out.cleanup.push({ step: 'delete-ecosystem', ecosystemId, ...del });
    }
  }

  const outPath = process.env.TEMP + '\\phase2_jp_live_result.json';
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

  console.log(JSON.stringify({
    outPath,
    error: out.error || null,
    ecosystemId: out.summary?.ecosystemId || null,
    foundBots: out.summary?.foundBots ?? null,
    foundListings: out.summary?.foundListings ?? null,
    humanAvatarPass: out.summary?.checks?.humanAvatarPass ?? null,
    japaneseSportNamePass: out.summary?.checks?.japaneseSportNamePass ?? null,
  }, null, 2));
})();
