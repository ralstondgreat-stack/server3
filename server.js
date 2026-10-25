'use strict';
const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 10000;
const devices = new Map();       // deviceId -> device state
const parentTokens = new Map();  // token -> deviceId
const childTokens = new Map();   // token -> deviceId
const pairCodes = new Map();     // code -> {deviceId, expires}
const MAX_BODY = 64 * 1024;

function token() { return crypto.randomBytes(32).toString('hex'); }
function code() { return String(Math.floor(100000 + Math.random() * 900000)); }
function now() { return Date.now(); }
function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(data);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (Buffer.byteLength(data) > MAX_BODY) {
        reject(new Error('Body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (_) { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function auth(req, map) {
  const h = String(req.headers.authorization || '');
  if (!h.startsWith('Bearer ')) return null;
  const id = map.get(h.slice(7));
  return id ? devices.get(id) || null : null;
}
function clean() {
  const t = now();
  for (const [c, p] of pairCodes) if (p.expires < t) pairCodes.delete(c);
  for (const [id, d] of devices) {
    d.messages = d.messages.filter(m => t - m.createdAt < 7 * 24 * 60 * 60 * 1000);
    d.events = d.events.filter(e => t - e.createdAt < 30 * 24 * 60 * 60 * 1000);
  }
}
function enqueueMessage(d, from, message) {
  const item = { id: crypto.randomUUID(), from, message, createdAt: now(), delivered: false };
  d.messages.push(item);
  return item;
}
function enqueueEvent(d, type, message) {
  const item = { id: crypto.randomUUID(), type, message, createdAt: now(), acknowledged: false };
  d.events.push(item);
  return item;
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return json(res, 204, {});
  try {
    clean();
    const u = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && u.pathname === '/health')
      return json(res, 200, { ok: true, service: 'Guardian Render relay', version: '1.3.0' });

    if (req.method === 'POST' && u.pathname === '/v1/pair/start') {
      const b = await readBody(req);
      const label = String(b.parentLabel || 'Guardian Parent').slice(0, 60);
      const deviceId = crypto.randomUUID();
      const parentToken = token();
      const d = {
        id: deviceId, parentLabel: label, childLabel: 'Unpaired Kid',
        parentOnline: true, childOnline: false, parentSeen: now(), childSeen: 0,
        messages: [], events: []
      };
      devices.set(deviceId, d);
      parentTokens.set(parentToken, deviceId);
      let pairingCode = code();
      while (pairCodes.has(pairingCode)) pairingCode = code();
      pairCodes.set(pairingCode, { deviceId, expires: now() + 10 * 60 * 1000 });
      return json(res, 200, { deviceId, parentToken, pairingCode, expiresInSeconds: 600 });
    }

    if (req.method === 'POST' && u.pathname === '/v1/pair/claim') {
      const b = await readBody(req);
      const pairingCode = String(b.code || '').trim();
      const p = pairCodes.get(pairingCode);
      if (!p || p.expires < now()) return json(res, 401, { error: 'Pairing code invalid or expired' });
      const d = devices.get(p.deviceId);
      if (!d) return json(res, 404, { error: 'Parent session not found' });
      pairCodes.delete(pairingCode);
      const childToken = token();
      childTokens.set(childToken, d.id);
      d.childLabel = String(b.childLabel || 'Guardian Kid').slice(0, 60);
      d.childSeen = now();
      d.childOnline = true;
      enqueueEvent(d, 'paired', 'Kid device approved pairing: ' + d.childLabel);
      return json(res, 200, { deviceId: d.id, childToken, parentLabel: d.parentLabel });
    }

    if (req.method === 'POST' && u.pathname === '/v1/parent/message') {
      const d = auth(req, parentTokens);
      if (!d) return json(res, 401, { error: 'Invalid parent token' });
      const b = await readBody(req);
      const message = String(b.message || '').trim();
      if (!message || message.length > 1000) return json(res, 400, { error: 'Message must be 1-1000 characters' });
      d.parentSeen = now();
      const item = enqueueMessage(d, 'parent', message);
      return json(res, 200, { ok: true, id: item.id, queued: true });
    }

    if (req.method === 'POST' && u.pathname === '/v1/kid/message') {
      const d = auth(req, childTokens);
      if (!d) return json(res, 401, { error: 'Invalid kid token' });
      const b = await readBody(req);
      const message = String(b.message || '').trim();
      if (!message || message.length > 1000) return json(res, 400, { error: 'Message must be 1-1000 characters' });
      d.childSeen = now();
      const item = enqueueMessage(d, 'kid', message);
      return json(res, 200, { ok: true, id: item.id, queued: true });
    }

    if (req.method === 'POST' && u.pathname === '/v1/kid/sos') {
      const d = auth(req, childTokens);
      if (!d) return json(res, 401, { error: 'Invalid kid token' });
      const b = await readBody(req);
      const message = String(b.message || 'SOS: Please contact me.').slice(0, 500);
      d.childSeen = now();
      const item = enqueueEvent(d, 'sos', message);
      return json(res, 200, { ok: true, id: item.id, queued: true });
    }

    if (req.method === 'GET' && u.pathname === '/v1/parent/inbox') {
      const d = auth(req, parentTokens);
      if (!d) return json(res, 401, { error: 'Invalid parent token' });
      d.parentSeen = now();
      const messages = d.messages.filter(m => m.from === 'kid' && !m.delivered);
      const events = d.events.filter(e => !e.acknowledged);
      messages.forEach(m => m.delivered = true);
      events.forEach(e => e.acknowledged = true);
      return json(res, 200, {
        deviceId: d.id, childLabel: d.childLabel,
        childOnline: now() - d.childSeen < 45000,
        childLastSeen: d.childSeen, messages, events
      });
    }

    if (req.method === 'GET' && u.pathname === '/v1/kid/inbox') {
      const d = auth(req, childTokens);
      if (!d) return json(res, 401, { error: 'Invalid kid token' });
      d.childSeen = now();
      const messages = d.messages.filter(m => m.from === 'parent' && !m.delivered);
      messages.forEach(m => m.delivered = true);
      return json(res, 200, {
        parentLabel: d.parentLabel,
        parentOnline: now() - d.parentSeen < 45000,
        parentLastSeen: d.parentSeen, messages
      });
    }

    if (req.method === 'POST' && u.pathname === '/v1/parent/heartbeat') {
      const d = auth(req, parentTokens);
      if (!d) return json(res, 401, { error: 'Invalid parent token' });
      d.parentSeen = now();
      return json(res, 200, { ok: true, childOnline: now() - d.childSeen < 45000 });
    }

    if (req.method === 'POST' && u.pathname === '/v1/kid/heartbeat') {
      const d = auth(req, childTokens);
      if (!d) return json(res, 401, { error: 'Invalid kid token' });
      d.childSeen = now();
      return json(res, 200, { ok: true, parentOnline: now() - d.parentSeen < 45000 });
    }

    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    return json(res, 400, { error: e.message || 'Bad request' });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log('Guardian relay listening on ' + PORT));
