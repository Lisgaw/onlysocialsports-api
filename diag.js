const { Pool } = require("pg");
require("dotenv").config();

async function testConnection(name, connectionString) {
  console.log(`--- Testing ${name} ---`);
  if (!connectionString) {
    console.log(`${name} is not defined in .env`);
    return;
  }
  const pool = new Pool({ connectionString });
  try {
    const res = await pool.query("SELECT current_user, current_database();");
    console.log(`Success:`, res.rows[0]);
  } catch (err) {
    console.log(`Error Status: ${err.code || "No Code"}`);
    console.log(`Error Message: ${err.message}`);
  } finally {
    await pool.end();
  }
}

(async () => {
  await testConnection("DIRECT_URL", process.env.DIRECT_URL);
  await testConnection("DATABASE_URL", process.env.DATABASE_URL);
})();
