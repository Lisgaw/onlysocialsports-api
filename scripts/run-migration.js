/**
 * OnlySocialSports — Run SQL Migration
 * Runs the Supabase migration via direct PostgreSQL connection
 */
const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

async function runMigration() {
  // Supabase direct connection (Frankfurt eu-central-1)
  const connectionString = 'postgresql://postgres:7U5Zab6YPA4h6xoO@db.ffduouvqqayyookkgcjo.supabase.co:5432/postgres';

  console.log('🚀 Connecting to Supabase (Frankfurt)...');
  
  const client = new Client({
    connectionString,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    console.log('✅ Connected to Supabase PostgreSQL');

    // Read the SQL migration file
    const sqlPath = path.join(__dirname, '..', 'sports_partner_mobile', 'backend', 'db', 'migrations', '001_initial_schema.sql');
    const sql = fs.readFileSync(sqlPath, 'utf8');
    console.log(`📄 Read SQL migration (${sql.length} chars)`);

    // Run the migration
    console.log('⚙️  Running migration...');
    await client.query(sql);
    console.log('✅ Migration completed successfully!');

    // Verify tables created
    const result = await client.query(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name;
    `);
    console.log(`✅ Tables created: ${result.rows.length}`);
    console.log(result.rows.map(r => r.table_name).join(', '));

  } catch (err) {
    console.error('❌ Migration error:', err.message);
    if (err.code) console.error('   Error code:', err.code);
    if (err.detail) console.error('   Detail:', err.detail);
  } finally {
    await client.end();
    console.log('🔌 Disconnected');
  }
}

runMigration();
