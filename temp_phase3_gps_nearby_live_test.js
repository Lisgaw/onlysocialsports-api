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

(async () => {
  const out = {
    phase: 'phase-3-live-gps-listing-and-nearby-validation',
    baseUrl: base,
    checks: [],
    cleanup: [],
  };

  let adminToken = null;
  let userToken = null;
  let userId = null;
  let listingId = null;

  const slug = Math.random().toString(36).replace(/[^a-z]/g, '').slice(0, 6) || 'qatest';
  const ts = Date.now();

  try {
    const adminLogin = await req('POST', '/auth/login', null, {
      email: 'admin@sporpartner.com',
      password: 'Admin123456!',
    });
    out.checks.push({ step: 'admin-login', ...adminLogin });
    if (!adminLogin.ok) throw new Error('admin login failed');
    adminToken = adminLogin.data.accessToken;

    const sports = await req('GET', '/sports', null, undefined);
    out.checks.push({ step: 'sports-fetch', ...sports });
    if (!sports.ok || !sports.data?.data?.length) throw new Error('sports fetch failed');
    const sportId = sports.data.data[0].id;

    const reg = await req('POST', '/auth/register', null, {
      name: `QA Delta ${slug}`,
      email: `qa.delta.${ts}@testmail.local`,
      password: 'TempPass123!',
    });
    out.checks.push({ step: 'register-user', ...reg });
    if (!reg.ok) throw new Error('register failed');
    userToken = reg.data.accessToken;
    userId = reg.data.user.id;

    const dt = new Date(Date.now() + 2 * 3600 * 1000).toISOString();
    const create = await req('POST', '/listings', userToken, {
      type: 'PARTNER',
      title: `QA GPS ${slug}`,
      description: 'QA gps listing validation',
      sportId,
      maxParticipants: 2,
      cityName: 'Istanbul',
      districtName: 'Kadikoy',
      dateTime: dt,
      latitude: 41.0082,
      longitude: 28.9784,
    });
    out.checks.push({ step: 'create-listing-with-gps-fields', ...create });
    if (!create.ok) throw new Error('listing create failed');

    listingId = create.data?.listing?.id;

    const detail = await req('GET', `/listings/${listingId}`, userToken, undefined);
    out.checks.push({ step: 'listing-detail', ...detail });

    const listing = detail.data || {};
    const latitude = listing.latitude;
    const longitude = listing.longitude;

    const listWithGpsQuery = await req('GET', '/listings?latitude=41.0082&longitude=28.9784&page=1&pageSize=10', userToken, undefined);
    out.checks.push({ step: 'listings-query-with-gps-params', ...listWithGpsQuery });

    const nearby = await req('GET', '/listings/nearby?latitude=41.0082&longitude=28.9784', userToken, undefined);
    out.checks.push({ step: 'nearby-endpoint-probe', ...nearby });

    const sampleListing = (listWithGpsQuery.data?.data || [])[0] || {};

    out.summary = {
      listingId,
      createStatus: create.status,
      listingLatitude: latitude ?? null,
      listingLongitude: longitude ?? null,
      gpsPersisted: latitude !== undefined && latitude !== null && longitude !== undefined && longitude !== null,
      listWithGpsStatus: listWithGpsQuery.status,
      listWithGpsHasDistanceField: Object.prototype.hasOwnProperty.call(sampleListing, 'distance') || Object.prototype.hasOwnProperty.call(sampleListing, 'distanceToUserM'),
      nearbyStatus: nearby.status,
      nearbyMessage: nearby.data?.message || nearby.data?.raw || null,
      nearbyFeatureExists: nearby.ok,
    };
  } catch (e) {
    out.error = String(e?.message || e);
  } finally {
    if (listingId && userToken) {
      const delListing = await req('DELETE', `/listings/${listingId}`, userToken, undefined);
      out.cleanup.push({ step: 'delete-listing', listingId, ...delListing });
    }
    if (userId && adminToken) {
      const delUser = await req('DELETE', `/admin/users/${userId}`, adminToken, undefined);
      out.cleanup.push({ step: 'delete-user', userId, ...delUser });
    }
  }

  const outPath = process.env.TEMP + '\\phase3_gps_nearby_live_result.json';
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

  console.log(JSON.stringify({
    outPath,
    error: out.error || null,
    listingId: out.summary?.listingId || null,
    gpsPersisted: out.summary?.gpsPersisted ?? null,
    nearbyFeatureExists: out.summary?.nearbyFeatureExists ?? null,
    nearbyStatus: out.summary?.nearbyStatus ?? null,
  }, null, 2));
})();
