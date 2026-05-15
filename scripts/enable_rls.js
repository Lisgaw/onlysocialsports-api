// Enable RLS on all tables via direct pg connection
const { Client } = require('pg');

async function main() {
  // Try both connection strings
  const connStrings = [
    {
      name: 'Pooler (6543)',
      url: 'postgresql://postgres.ffduouvqqayyookkgcjo:7U5Zab6YPA4h6xoO@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'
    },
    {
      name: 'Pooler (5432)',
      url: 'postgresql://postgres.ffduouvqqayyookkgcjo:7U5Zab6YPA4h6xoO@aws-0-eu-central-1.pooler.supabase.com:5432/postgres'
    },
    {
      name: 'Direct',
      url: 'postgresql://postgres:7U5Zab6YPA4h6xoO@db.ffduouvqqayyookkgcjo.supabase.co:5432/postgres'
    },
    {
      name: 'New password pooler (6543)',
      url: 'postgresql://postgres.ffduouvqqayyookkgcjo:Nesimidadas8266%2B@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'
    },
    {
      name: 'New password direct',
      url: 'postgresql://postgres:Nesimidadas8266%2B@db.ffduouvqqayyookkgcjo.supabase.co:5432/postgres'
    }
  ];

  for (const cs of connStrings) {
    console.log(`\n--- Trying: ${cs.name} ---`);
    const client = new Client({
      connectionString: cs.url,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 10000,
    });
    try {
      await client.connect();
      console.log('Connected!');
      
      // Check current RLS status
      const res = await client.query(`
        SELECT tablename, rowsecurity 
        FROM pg_tables 
        WHERE schemaname = 'public' 
        ORDER BY tablename
      `);
      console.log('Current RLS status:');
      for (const row of res.rows) {
        console.log(`  ${row.rowsecurity ? '✅' : '❌'} ${row.tablename}: RLS ${row.rowsecurity ? 'ON' : 'OFF'}`);
      }

      // Enable RLS on all tables
      const tables = res.rows.filter(r => !r.rowsecurity).map(r => r.tablename);
      if (tables.length > 0) {
        console.log(`\nEnabling RLS on ${tables.length} tables...`);
        for (const t of tables) {
          await client.query(`ALTER TABLE "${t}" ENABLE ROW LEVEL SECURITY`);
          console.log(`  ✅ RLS enabled: ${t}`);
        }

        // Create public read policies for reference tables
        const publicTables = ['sports', 'cities', 'districts', 'countries'];
        for (const t of publicTables) {
          try {
            await client.query(`CREATE POLICY "Public read: ${t}" ON "${t}" FOR SELECT USING (true)`);
            console.log(`  📖 Public read policy: ${t}`);
          } catch (e) {
            if (e.message.includes('already exists')) {
              console.log(`  📖 Policy already exists: ${t}`);
            } else {
              console.log(`  ⚠️ Policy error for ${t}: ${e.message}`);
            }
          }
        }
      }

      // Verify
      const verify = await client.query(`
        SELECT tablename, rowsecurity 
        FROM pg_tables 
        WHERE schemaname = 'public' 
        ORDER BY tablename
      `);
      console.log('\n--- FINAL RLS STATUS ---');
      let allGood = true;
      for (const row of verify.rows) {
        console.log(`  ${row.rowsecurity ? '✅' : '❌'} ${row.tablename}`);
        if (!row.rowsecurity) allGood = false;
      }
      console.log(allGood ? '\n🎉 ALL TABLES PROTECTED!' : '\n⚠️ Some tables still unprotected');

      await client.end();
      return; // Success, stop trying other connections
    } catch (e) {
      console.log(`Failed: ${e.message}`);
      try { await client.end(); } catch (_) {}
    }
  }
  console.log('\n❌ ALL CONNECTION ATTEMPTS FAILED');
  console.log('You need to run the SQL manually in Supabase Dashboard SQL Editor.');
}

main();
