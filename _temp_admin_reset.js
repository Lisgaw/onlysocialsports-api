const https = require('https');
const bcrypt = require('bcryptjs');

async function main() {
  const hash = await bcrypt.hash('Admin123456!', 10);
  const data = JSON.stringify({ password: hash });
  
  const opts = {
    hostname: 'ffduouvqqayyookkgcjo.supabase.co',
    path: '/rest/v1/users?id=eq.user_be4dea7c-129f-459e-815c-760153c96a9a',
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'apikey': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZmZHVvdXZxcWF5eW9va2tnY2pvIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NjQwODY0MCwiZXhwIjoyMDkxOTg0NjQwfQ.pgd78QILs5kWQl_9XcF03A370gOm2dsCfnsKVY7cfXA',
      'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZmZHVvdXZxcWF5eW9va2tnY2pvIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NjQwODY0MCwiZXhwIjoyMDkxOTg0NjQwfQ.pgd78QILs5kWQl_9XcF03A370gOm2dsCfnsKVY7cfXA',
      'Prefer': 'return=minimal',
      'Content-Length': data.length,
    }
  };

  return new Promise((resolve) => {
    const req = https.request(opts, res => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => { console.log('Status:', res.statusCode); console.log('Body:', b); resolve(); });
    });
    req.write(data);
    req.end();
  });
}

main();
