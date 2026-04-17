'use strict';

/**
 * DB Helpers — snake_case ↔ camelCase conversion + common utilities
 */

// ─── Case Conversion ───────────────────────────────────────────────────────

function snakeToCamel(str) {
  return str.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
}

function camelToSnake(str) {
  return str.replace(/[A-Z]/g, c => '_' + c.toLowerCase());
}

/** Convert object keys snake_case → camelCase (recursive) */
function toCamel(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(toCamel);
  if (obj instanceof Date) return obj;
  if (typeof obj !== 'object') return obj;
  const result = {};
  for (const [key, val] of Object.entries(obj)) {
    const ck = snakeToCamel(key);
    result[ck] = (val !== null && typeof val === 'object' && !(val instanceof Date))
      ? toCamel(val)
      : val;
  }
  return result;
}

/** Convert object keys camelCase → snake_case (recursive, skip JSONB arrays) */
function toSnake(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj; // JSONB arrays stay as-is
  if (obj instanceof Date) return obj;
  if (typeof obj !== 'object') return obj;
  const result = {};
  for (const [key, val] of Object.entries(obj)) {
    const sk = camelToSnake(key);
    result[sk] = val;
  }
  return result;
}

// ─── User-Specific Transformations ──────────────────────────────────────────

/** DB row → API response (user). Renames level→userLevel, removes password. */
function toUserResponse(row) {
  if (!row) return null;
  const u = toCamel(row);
  if ('level' in u) { u.userLevel = u.level; delete u.level; }
  delete u.password;
  return u;
}

/** API body → DB columns (user). Renames userLevel→level. */
function fromUserBody(body) {
  const s = toSnake(body);
  if ('user_level' in s) { s.level = s.user_level; delete s.user_level; }
  return s;
}

// ─── Pagination ─────────────────────────────────────────────────────────────

function parsePagination(query) {
  const page = Math.max(1, parseInt(query.page) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 20));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ─── Cursor Pagination (for listings/feed) ──────────────────────────────────

function parseCursor(query) {
  const limit = Math.min(100, Math.max(1, parseInt(query.limit) || 20));
  const cursor = query.cursor || null;
  return { limit, cursor };
}

module.exports = {
  toCamel,
  toSnake,
  toUserResponse,
  fromUserBody,
  parsePagination,
  parseCursor,
  snakeToCamel,
  camelToSnake,
};
