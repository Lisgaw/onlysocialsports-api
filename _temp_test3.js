const https = require('https');

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : '';
    const opts = {
      hostname: 'onlysocialsports-api.vercel.app',
      path,
      method,
      headers: { 'Content-Type': 'application/json', ...headers, ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}) },
    };
    const req = https.request(opts, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(b) }); }
        catch { resolve({ status: res.statusCode, data: b }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function main() {
  // Login
  const login = await request('POST', '/api/auth/login', { email: 'admin@sporpartner.com', password: 'Admin123456!' });
  if (login.status !== 200) { console.log('Login failed:', login.data); return; }
  const token = login.data.accessToken;
  console.log('Logged in.');

  // Delete the existing ecosystem eco_285424f5-36f2-4a1a-9c65-137b624f7863
  console.log('Deleting eco_285424f5...');
  const del = await request('DELETE', '/api/admin/ecosystems/eco_285424f5-36f2-4a1a-9c65-137b624f7863', null, { Authorization: `Bearer ${token}` });
  console.log('Delete:', del.status, JSON.stringify(del.data).slice(0, 300));

  // Verify empty
  const list = await request('GET', '/api/admin/ecosystems', null, { Authorization: `Bearer ${token}` });
  console.log('List after delete:', JSON.stringify(list.data).slice(0, 200));

  // Now create fresh
  console.log('\nCreating fresh Istanbul ecosystem...');
  const eco = await request('POST', '/api/admin/ecosystems', {
    scope: 'CITY',
    countryCode: 'TR',
    cityId: 'c1',
    cityName: 'İstanbul',
    sportIds: ['football', 'basketball', 'tennis'],
    listingType: 'PARTNER',
    botsPerCity: 4,
  }, { Authorization: `Bearer ${token}` });
  console.log('Create:', eco.status);
  console.log(JSON.stringify(eco.data, null, 2));
}

main().catch(console.error);
