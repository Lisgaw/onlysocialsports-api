const { Client } = require('pg');
const c = new Client({
  host: 'aws-0-eu-central-1.pooler.supabase.com',
  port: 6543,
  database: 'postgres',
  user: 'postgres.ffduouvqqayyookkgcjo',
  password: '7U5Zab6YPA4h6xoO',
  ssl: { rejectUnauthorized: false }
});
c.connect()
  .then(() => c.query("SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"))
  .then(r => { console.log(JSON.stringify(r.rows, null, 2)); c.end(); })
  .catch(e => { console.error('ERROR:', e.message); c.end().catch(() => {}); });
