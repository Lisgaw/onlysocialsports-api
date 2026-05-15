const fs = require('fs');

const base = 'https://api.onlysocialsport.com/api';

function j(v){ return JSON.stringify(v); }

async function req(method, path, token, body){
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

(async () => {
  const out = {
    phase: 'phase-1-live-migration-and-group-rating-validation',
    baseUrl: base,
    results: [],
    cleanup: [],
  };

  let adminToken = null;
  let idA = null;
  let idB = null;
  let idC = null;
  let tokenA = null;
  let tokenB = null;
  let tokenC = null;
  let listingId = null;

  try {
    const adminLogin = await req('POST', '/auth/login', null, {
      email: 'admin@sporpartner.com',
      password: 'Admin123456!',
    });
    out.results.push({ step: 'admin-login', ...adminLogin });
    if (!adminLogin.ok) throw new Error('admin login failed');
    adminToken = adminLogin.data.accessToken;

    const migrate = await req('POST', '/admin/migrate', adminToken, {});
    out.results.push({ step: 'admin-migrate-check', ...migrate });

    const sports = await req('GET', '/sports', null, undefined);
    out.results.push({ step: 'sports-fetch', ...sports });
    if (!sports.ok || !sports.data?.data?.length) {
      throw new Error('sports fetch failed');
    }
    const sportId = sports.data.data[0].id;

    const ts = Date.now();
    const slug = Math.random().toString(36).replace(/[^a-z]/g, '').slice(0, 6) || 'qatest';
    const pwd = 'TempPass123!';
    const regA = await req('POST', '/auth/register', null, {
      name: `QA Alpha ${slug}`,
      email: `qa.a.${ts}@testmail.local`,
      password: pwd,
    });
    const regB = await req('POST', '/auth/register', null, {
      name: `QA Bravo ${slug}`,
      email: `qa.b.${ts}@testmail.local`,
      password: pwd,
    });
    const regC = await req('POST', '/auth/register', null, {
      name: `QA Charlie ${slug}`,
      email: `qa.c.${ts}@testmail.local`,
      password: pwd,
    });

    out.results.push({ step: 'register-a', ...regA });
    out.results.push({ step: 'register-b', ...regB });
    out.results.push({ step: 'register-c', ...regC });
    if (!regA.ok || !regB.ok || !regC.ok) {
      throw new Error('register failed');
    }

    tokenA = regA.data.accessToken;
    tokenB = regB.data.accessToken;
    tokenC = regC.data.accessToken;
    idA = regA.data.user.id;
    idB = regB.data.user.id;
    idC = regC.data.user.id;

    const dt = new Date(Date.now() + 20 * 3600 * 1000).toISOString();
    const create = await req('POST', '/listings', tokenA, {
      type: 'PARTNER',
      title: `QA Group Rating ${slug}`,
      description: 'QA group rating flow validation',
      sportId,
      maxParticipants: 3,
      cityName: 'Istanbul',
      districtName: 'Kadikoy',
      dateTime: dt,
    });
    out.results.push({ step: 'create-group-listing', ...create });
    if (!create.ok) throw new Error('create listing failed');
    listingId = create.data?.listing?.id;

    const applyB = await req('POST', `/listings/${listingId}/interest`, tokenB, {
      message: 'B apply',
    });
    const applyC = await req('POST', `/listings/${listingId}/interest`, tokenC, {
      message: 'C apply',
    });
    out.results.push({ step: 'apply-b', ...applyB });
    out.results.push({ step: 'apply-c', ...applyC });
    if (!applyB.ok || !applyC.ok) throw new Error('apply failed');

    const respIdB = applyB.data.responseId;
    const respIdC = applyC.data.responseId;

    const acceptB = await req('PATCH', `/listings/${listingId}/interests/${respIdB}`, tokenA, {
      action: 'ACCEPTED',
    });
    const acceptC = await req('PATCH', `/listings/${listingId}/interests/${respIdC}`, tokenA, {
      action: 'ACCEPTED',
    });
    out.results.push({ step: 'accept-b', ...acceptB });
    out.results.push({ step: 'accept-c', ...acceptC });

    let matchId =
      acceptC.data?.data?.match?.id ||
      acceptB.data?.data?.match?.id ||
      null;

    if (!matchId) {
      const mlist = await req('GET', '/matches', tokenA, undefined);
      out.results.push({ step: 'matches-a', ...mlist });
      if (mlist.ok) {
        const cand = (mlist.data?.data || []).find((m) => m.listingId === listingId);
        if (cand) matchId = cand.id;
      }
    }

    const ap1 = await req('PATCH', `/matches/${matchId}/approve`, tokenA, {});
    const ap2 = await req('PATCH', `/matches/${matchId}/approve`, tokenB, {});
    const md = await req('GET', `/matches/${matchId}`, tokenA, undefined);
    out.results.push({ step: 'approve-a', ...ap1 });
    out.results.push({ step: 'approve-b', ...ap2 });
    out.results.push({ step: 'match-detail-after-approve', ...md });

    const rateAB = await req('POST', '/ratings', tokenA, {
      matchId,
      rateeId: idB,
      score: 5,
      comment: 'QA A->B',
    });
    const rateAC = await req('POST', '/ratings', tokenA, {
      matchId,
      rateeId: idC,
      score: 4,
      comment: 'QA A->C',
    });
    out.results.push({ step: 'rate-a-b', ...rateAB });
    out.results.push({ step: 'rate-a-c', ...rateAC });
  } catch (e) {
    out.error = String(e?.message || e);
  } finally {
    if (listingId && tokenA) {
      const delListing = await req('DELETE', `/listings/${listingId}`, tokenA, undefined);
      out.cleanup.push({ step: 'delete-listing', listingId, ...delListing });
    }

    if (adminToken) {
      for (const uid of [idA, idB, idC].filter(Boolean)) {
        const delUser = await req('DELETE', `/admin/users/${uid}`, adminToken, undefined);
        out.cleanup.push({ step: 'delete-user', userId: uid, ...delUser });
      }
    }
  }

  const outPath = process.env.TEMP + '\\phase1_live_result.json';
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

  const summary = {
    outPath,
    error: out.error || null,
    rateAB: out.results.find((x) => x.step === 'rate-a-b')?.status ?? null,
    rateAC: out.results.find((x) => x.step === 'rate-a-c')?.status ?? null,
    matchStatus:
      out.results.find((x) => x.step === 'match-detail-after-approve')?.data?.data?.status ??
      null,
  };

  console.log(JSON.stringify(summary, null, 2));
})();
