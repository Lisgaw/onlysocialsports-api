'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const tables = {
  users: [],
  listings: [],
  matches: [],
  ratings: [],
  notifications: [],
  match_participants: [],
  interests: [],
};

let simulateLegacyRatingUniqueConstraint = false;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function whereAll(rows, filters) {
  const entries = Object.entries(filters || {});
  if (entries.length === 0) return rows;
  return rows.filter((row) => entries.every(([key, val]) => row[key] === val));
}

function resetTables() {
  tables.users = [
    { id: 'u_owner', name: 'Owner', average_rating: 0, rating_count: 0 },
    { id: 'u_a', name: 'Alice', average_rating: 0, rating_count: 0 },
    { id: 'u_b', name: 'Bob', average_rating: 0, rating_count: 0 },
    { id: 'u_stranger', name: 'Mallory', average_rating: 0, rating_count: 0 },
  ];

  tables.listings = [
    {
      id: 'listing_group',
      type: 'PARTNER',
      max_participants: 4,
      user_id: 'u_owner',
      sport_id: 'sport_1',
    },
  ];

  tables.matches = [
    {
      id: 'match_group',
      listing_id: 'listing_group',
      user1_id: 'u_owner',
      user2_id: 'u_a',
      status: 'COMPLETED',
      source: 'LISTING',
    },
  ];

  tables.ratings = [];
  tables.notifications = [];
  tables.match_participants = [
    { id: 'mp_1', match_id: 'match_group', user_id: 'u_owner', role: 'OWNER' },
    { id: 'mp_2', match_id: 'match_group', user_id: 'u_a', role: 'PARTICIPANT' },
    { id: 'mp_3', match_id: 'match_group', user_id: 'u_b', role: 'PARTICIPANT' },
  ];
  tables.interests = [];
  simulateLegacyRatingUniqueConstraint = false;
}

function supabaseBuilder(tableName) {
  const state = {
    tableName,
    mode: 'select',
    filters: [],
  };

  function execute() {
    const table = tables[state.tableName] || [];
    const filtered = table.filter((row) => state.filters.every((fn) => fn(row)));

    if (state.mode === 'delete') {
      const keep = table.filter((row) => !state.filters.every((fn) => fn(row)));
      tables[state.tableName] = keep;
      return { data: clone(filtered), error: null };
    }

    return { data: clone(filtered), error: null };
  }

  const builder = {
    select() {
      state.mode = 'select';
      return builder;
    },
    delete() {
      state.mode = 'delete';
      return builder;
    },
    insert(rows) {
      const input = Array.isArray(rows) ? rows : [rows];
      const table = tables[state.tableName] || [];
      for (const row of input) table.push(clone(row));
      tables[state.tableName] = table;
      return Promise.resolve({ data: clone(input), error: null });
    },
    eq(field, value) {
      state.filters.push((row) => row[field] === value);
      return builder;
    },
    in(field, values) {
      const allowed = new Set(values || []);
      state.filters.push((row) => allowed.has(row[field]));
      return builder;
    },
    gt(field, value) {
      state.filters.push((row) => Number(row[field] || 0) > Number(value));
      return builder;
    },
    order() {
      return builder;
    },
    then(onFulfilled, onRejected) {
      return Promise.resolve(execute()).then(onFulfilled, onRejected);
    },
  };

  return builder;
}

const mockDb = {
  raw() {
    return {
      from(tableName) {
        return supabaseBuilder(tableName);
      },
    };
  },
  async findById(tableName, id) {
    const row = (tables[tableName] || []).find((item) => item.id === id);
    return row ? clone(row) : null;
  },
  async findOne(tableName, filters) {
    const row = whereAll(tables[tableName] || [], filters)[0];
    return row ? clone(row) : null;
  },
  async insert(tableName, payload) {
    const row = clone(payload);
    if (!row.id) row.id = `${tableName}_${Math.random().toString(16).slice(2)}`;

    if (tableName === 'ratings') {
      const rows = tables.ratings || [];

      if (simulateLegacyRatingUniqueConstraint) {
        const duplicateLegacy = rows.some(
          (r) => r.match_id === row.match_id && r.rater_id === row.rater_id,
        );
        if (duplicateLegacy) {
          throw new Error('duplicate key value violates unique constraint "ratings_match_id_rater_id_key"');
        }
      } else {
        const duplicateNew = rows.some(
          (r) =>
            r.match_id === row.match_id &&
            r.rater_id === row.rater_id &&
            r.ratee_id === row.ratee_id,
        );
        if (duplicateNew) {
          throw new Error('duplicate key value violates unique constraint "ratings_match_id_rater_id_ratee_id_key"');
        }
      }
    }

    if (!tables[tableName]) tables[tableName] = [];
    tables[tableName].push(row);
    return clone(row);
  },
  async update(tableName, id, patch) {
    const table = tables[tableName] || [];
    const idx = table.findIndex((item) => item.id === id);
    if (idx < 0) return null;
    table[idx] = { ...table[idx], ...clone(patch) };
    tables[tableName] = table;
    return clone(table[idx]);
  },
  async query(tableName, options = {}) {
    const rows = whereAll(tables[tableName] || [], options.filters || {});
    return clone(rows);
  },
};

const mockAuth = {
  generateTokens() {
    return { accessToken: 'access', refreshToken: 'refresh' };
  },
  verifyRefreshToken() {
    return { sub: 'u_owner' };
  },
  authMiddleware(req, _res, next) {
    req.userId = req.headers['x-user-id'] || 'u_owner';
    next();
  },
};

const dbModulePath = require.resolve('../db/supabase');
const authModulePath = require.resolve('../middleware/auth');

delete require.cache[dbModulePath];
delete require.cache[authModulePath];
require.cache[dbModulePath] = {
  id: dbModulePath,
  filename: dbModulePath,
  loaded: true,
  exports: mockDb,
};
require.cache[authModulePath] = {
  id: authModulePath,
  filename: authModulePath,
  loaded: true,
  exports: mockAuth,
};

const app = require('../api/index');

let server;
let baseUrl;

test.before(async () => {
  resetTables();
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  if (!server) return;
  await new Promise((resolve) => server.close(resolve));
});

test.beforeEach(() => {
  resetTables();
});

async function postRating({ userId, body }) {
  const response = await fetch(`${baseUrl}/api/ratings`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-user-id': userId,
    },
    body: JSON.stringify(body),
  });

  return {
    status: response.status,
    json: await response.json(),
  };
}

test('group match allows rating multiple different participants', async () => {
  const first = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_a', score: 4, comment: 'Good game' },
  });
  const second = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_b', score: 5, comment: 'Great teamwork' },
  });

  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
  assert.equal(tables.ratings.length, 2);

  const ratees = tables.ratings.map((row) => row.ratee_id).sort();
  assert.deepEqual(ratees, ['u_a', 'u_b']);

  const ratedA = tables.users.find((u) => u.id === 'u_a');
  const ratedB = tables.users.find((u) => u.id === 'u_b');
  assert.equal(ratedA.average_rating, 4);
  assert.equal(ratedA.rating_count, 1);
  assert.equal(ratedB.average_rating, 5);
  assert.equal(ratedB.rating_count, 1);
});

test('group match updates existing rating for the same target', async () => {
  const first = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_a', score: 2, comment: 'First' },
  });
  const second = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_a', score: 5, comment: 'Updated' },
  });

  assert.equal(first.status, 201);
  assert.equal(second.status, 200);
  assert.equal(tables.ratings.length, 1);
  assert.equal(tables.ratings[0].score, 5);
  assert.equal(tables.ratings[0].comment, 'Updated');
});

test('group match rejects rating attempts from non-participants', async () => {
  const response = await postRating({
    userId: 'u_stranger',
    body: { matchId: 'match_group', rateeId: 'u_a', score: 4 },
  });

  assert.equal(response.status, 403);
  assert.match(response.json.message, /katılımcısı değilsiniz/i);
  assert.equal(tables.ratings.length, 0);
});

test('group match returns migration hint when legacy ratings unique key is active', async () => {
  simulateLegacyRatingUniqueConstraint = true;

  const first = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_a', score: 4 },
  });
  const second = await postRating({
    userId: 'u_owner',
    body: { matchId: 'match_group', rateeId: 'u_b', score: 5 },
  });

  assert.equal(first.status, 201);
  assert.equal(second.status, 409);
  assert.match(second.json.message, /005_ratings_group_unique\.sql/i);
  assert.equal(tables.ratings.length, 1);
});