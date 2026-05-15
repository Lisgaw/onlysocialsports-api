'use strict';

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const DIRECT_URL = process.env.DIRECT_URL;
if (!DIRECT_URL) {
  console.error('DIRECT_URL is not set in backend/.env');
  process.exit(1);
}

async function main() {
  const sqlPath = path.join(__dirname, '..', 'db', 'migrations', '005_ratings_group_unique.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const pool = new Pool({
    connectionString: DIRECT_URL,
    ssl: { rejectUnauthorized: false },
  });

  const client = await pool.connect();
  try {
    await client.query(sql);

    const verify = await client.query(`
      SELECT conname
      FROM pg_constraint
      WHERE conrelid = 'ratings'::regclass
        AND conname IN ('ratings_match_id_rater_id_key', 'ratings_match_id_rater_id_ratee_id_key')
      ORDER BY conname
    `);

    const indexCheck = await client.query(`
      SELECT indexname
      FROM pg_indexes
      WHERE tablename = 'ratings'
        AND indexname = 'idx_ratings_match_rater'
    `);

    const names = verify.rows.map((r) => r.conname);
    const summary = {
      migration: '005_ratings_group_unique.sql',
      oldConstraintExists: names.includes('ratings_match_id_rater_id_key'),
      newConstraintExists: names.includes('ratings_match_id_rater_id_ratee_id_key'),
      idxRatingsMatchRaterExists: indexCheck.rows.length > 0,
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err.message || String(err));
  process.exit(1);
});
