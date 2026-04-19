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
  // 1. Login as admin
  console.log('1. Logging in as admin...');
  const login = await request('POST', '/api/auth/login', { email: 'admin@sporpartner.com', password: 'Admin123456!' });
  console.log('Login status:', login.status);
  if (login.status !== 200) { console.log('Login failed:', login.data); return; }
  const token = login.data.accessToken;
  console.log('Got token:', token.slice(0, 30) + '...');

  // 2. Create Istanbul ecosystem
  console.log('\n2. Creating Istanbul ecosystem...');
  const eco = await request('POST', '/api/admin/ecosystems', {
    scope: 'CITY',
    countryCode: 'TR',
    cityId: 'c1',
    cityName: 'İstanbul',
    sportIds: ['football', 'basketball', 'tennis', 'fitness', 'running', 'yoga'],
    listingType: 'BOTH',
    botsPerCity: 6,
    maxParticipants: 4,
    hourlyApplications: 2,
  }, { Authorization: `Bearer ${token}` });
  console.log('Ecosystem status:', eco.status);
  console.log('Ecosystem response:', JSON.stringify(eco.data, null, 2));

  // 3. Test ecosystem-tick
  console.log('\n3. Running ecosystem-tick...');
  const tick = await request('GET', '/api/cron/ecosystem-tick', null, {
    Authorization: 'Bearer OnlySocialSports2026SecretKey_Frankfurt_Lisgaw!@#$'
  });
  console.log('Tick status:', tick.status);
  console.log('Tick response:', JSON.stringify(tick.data, null, 2));
}

main().catch(console.error);
