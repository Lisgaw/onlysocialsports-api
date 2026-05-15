'use strict';

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const backendRoot = path.resolve(__dirname, '..');
const envPath = path.join(backendRoot, '.env');
const migrationPath = path.join(backendRoot, 'db', 'migrations', '006_venues_cache.sql');

function parseEnv(text) {
  const map = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    let value = line.slice(idx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    map.set(key, value);
  }
  return map;
}

function parseConnectionParts(rawUrl) {
  if (!rawUrl) return null;

  const url = new URL(rawUrl);
  const withoutProtocol = rawUrl.replace(/^postgres(?:ql)?:\/\//i, '');
  const atIdx = withoutProtocol.indexOf('@');
  if (atIdx < 0) return null;

  const credentials = withoutProtocol.slice(0, atIdx);
  const sepIdx = credentials.indexOf(':');
  if (sepIdx < 0) return null;

  const rawUser = credentials.slice(0, sepIdx);
  const rawPassword = credentials.slice(sepIdx + 1);

  return {
    host: url.hostname,
    port: Number(url.port || 5432),
    database: decodeURIComponent(url.pathname.replace(/^\//, '') || 'postgres'),
    user: decodeURIComponent(rawUser),
    userBase: decodeURIComponent(rawUser).split('.')[0],
    password: decodeURIComponent(rawPassword),
    rawUrl,
  };
}

function buildAttemptConfigs(parts, directParts) {
  const attempts = [];
  if (parts?.rawUrl) {
    attempts.push({
      label: 'DATABASE_URL(connectionString)',
      config: {
        connectionString: parts.rawUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });
  }

  if (directParts?.rawUrl) {
    attempts.push({
      label: 'DIRECT_URL(connectionString)',
      config: {
        connectionString: directParts.rawUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });
  }

  if (parts) {
    attempts.push({
      label: 'DATABASE_URL(manual user full)',
      config: {
        host: parts.host,
        port: parts.port,
        database: parts.database,
        user: parts.user,
        password: parts.password,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });

    attempts.push({
      label: 'DATABASE_URL(manual user base)',
      config: {
        host: parts.host,
        port: parts.port,
        database: parts.database,
        user: parts.userBase,
        password: parts.password,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });
  }

  if (directParts) {
    attempts.push({
      label: 'DIRECT_URL(manual user full)',
      config: {
        host: directParts.host,
        port: directParts.port,
        database: directParts.database,
        user: directParts.user,
        password: directParts.password,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });

    attempts.push({
      label: 'DIRECT_URL(manual user base)',
      config: {
        host: directParts.host,
        port: directParts.port,
        database: directParts.database,
        user: directParts.userBase,
        password: directParts.password,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 7000,
      },
    });
  }

  return attempts;
}

async function connectWithFallback(attempts) {
  const errors = [];
  for (const attempt of attempts) {
    const client = new Client(attempt.config);
    try {
      await client.connect();
      await client.query('select 1');
      console.log(`[OK] Connected via ${attempt.label}`);
      return { client, label: attempt.label, errors };
    } catch (error) {
      errors.push({
        label: attempt.label,
        code: error?.code || 'NO_CODE',
        message: error?.message || 'Unknown connection error',
      });
      try { await client.end(); } catch {}
    }
  }
  return { client: null, label: null, errors };
}

async function verifyMigration(client) {
  const tableRes = await client.query(
    `select exists (
      select 1 from information_schema.tables
      where table_schema = 'public' and table_name = 'venues_cache'
    ) as exists`
  );
  const tableExists = tableRes.rows?.[0]?.exists === true;

  const indexRes = await client.query(
    `select indexname from pg_indexes where schemaname = 'public' and tablename = 'venues_cache' order by indexname`
  );
  const indexes = (indexRes.rows || []).map(row => row.indexname);

  return { tableExists, indexes };
}

(async () => {
  try {
    const envText = fs.readFileSync(envPath, 'utf8');
    const env = parseEnv(envText);
    const databaseUrl = env.get('DATABASE_URL');
    const directUrl = env.get('DIRECT_URL');

    if (!databaseUrl && !directUrl) {
      console.error('No DATABASE_URL or DIRECT_URL found in backend/.env');
      process.exit(1);
    }

    const parts = parseConnectionParts(databaseUrl);
    const directParts = parseConnectionParts(directUrl);
    const attempts = buildAttemptConfigs(parts, directParts);

    const { client, label, errors } = await connectWithFallback(attempts);
    if (!client) {
      console.error('Could not establish a DB connection with any attempt.');
      for (const err of errors) {
        console.error(`[FAIL] ${err.label} :: ${err.code} :: ${err.message}`);
      }
      process.exit(2);
    }

    console.log(`Using connection: ${label}`);
    const sql = fs.readFileSync(migrationPath, 'utf8');
    await client.query(sql);
    console.log('Migration SQL executed.');

    const { tableExists, indexes } = await verifyMigration(client);
    console.log(`venues_cache exists: ${tableExists}`);
    console.log(`venues_cache indexes: ${indexes.join(', ')}`);

    await client.end();

    if (!tableExists) {
      process.exit(3);
    }
  } catch (error) {
    console.error('Migration runner failed:', error?.message || error);
    process.exit(1);
  }
})();
