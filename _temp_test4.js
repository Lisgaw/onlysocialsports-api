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
  const login = await request('POST', '/api/auth/login', { email: 'admin@sporpartner.com', password: 'Admin123456!' });
  if (login.status !== 200) { console.log('Login failed:', login.data); return; }
  const token = login.data.accessToken;
  const auth = { Authorization: `Bearer ${token}` };

  // List and delete ALL ecosystems
  const list = await request('GET', '/api/admin/ecosystems', null, auth);
  if (list.data.data && list.data.data.length > 0) {
    for (const eco of list.data.data) {
      console.log(`Deleting ${eco.id} (${eco.cityName})...`);
      const d = await request('DELETE', `/api/admin/ecosystems/${eco.id}`, null, auth);
      console.log('  ->', d.status, JSON.stringify(d.data).slice(0, 100));
    }
  }

  // Verify empty
  const list2 = await request('GET', '/api/admin/ecosystems', null, auth);
  console.log('After cleanup:', list2.data.data?.length || 0, 'ecosystems');

  // Create fresh
  console.log('\nCreating İstanbul ecosystem...');
  const eco = await request('POST', '/api/admin/ecosystems', {
    scope: 'CITY', countryCode: 'TR', cityId: 'c1', cityName: 'İstanbul',
    sportIds: ['football', 'basketball', 'tennis'],
    listingType: 'PARTNER', botsPerCity: 4,
  }, auth);
  console.log('Create:', eco.status);
  console.log(JSON.stringify(eco.data, null, 2));
}

main().catch(console.error);
