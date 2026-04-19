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

  // First delete existing ecosystem
  console.log('Deleting existing ecosystem...');
  const del = await request('DELETE', '/api/admin/ecosystems/eco_2fbb9150-8356-42d3-80c0-978c17bfb7fa', null, { Authorization: `Bearer ${token}` });
  console.log('Delete:', del.status, JSON.stringify(del.data).slice(0, 200));

  // Try to create ecosystem with a debug approach - check if botAutomation loaded
  console.log('\nChecking /api/admin/ecosystems GET...');
  const list = await request('GET', '/api/admin/ecosystems', null, { Authorization: `Bearer ${token}` });
  console.log('List:', list.status, JSON.stringify(list.data).slice(0, 300));

  // Create again
  console.log('\nCreating ecosystem...');
  const eco = await request('POST', '/api/admin/ecosystems', {
    scope: 'CITY',
    countryCode: 'TR',
    cityId: 'c1',
    cityName: 'İstanbul',
    sportIds: ['football', 'basketball', 'tennis'],
    listingType: 'PARTNER',
    botsPerCity: 4,
  }, { Authorization: `Bearer ${token}` });
  console.log('Create:', eco.status, JSON.stringify(eco.data, null, 2));
}

main().catch(console.error);
