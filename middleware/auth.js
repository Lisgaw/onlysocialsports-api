'use strict';
const jwt = require('jsonwebtoken');

if (!process.env.JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[FATAL] JWT_SECRET environment variable must be set in production. Refusing to start.');
  }
  console.warn('[SECURITY WARNING] JWT_SECRET is not set. Using insecure dev default. This is NOT safe for production!');
}
const JWT_SECRET = process.env.JWT_SECRET || 'sporpartner-dev-secret-2024';
const ACCESS_TOKEN_EXPIRY = '2h';
const REFRESH_TOKEN_EXPIRY = '30d';

function generateTokens(userId) {
  const accessToken = jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
  const refreshToken = jwt.sign({ sub: userId, type: 'refresh' }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
  const expiresAt = new Date(Date.now() + 2 * 3600 * 1000).toISOString();
  return { accessToken, refreshToken, expiresAt };
}

function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  const token = header.slice(7);
  try {
    const payload = verifyAccessToken(token);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ message: 'Token expired or invalid' });
  }
}

module.exports = { generateTokens, verifyRefreshToken, authMiddleware, JWT_SECRET };
