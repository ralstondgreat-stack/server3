const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const pairs = new Map();      // code -> { expiresAt, parentToken, used }
const tokens = new Map();     // bearer token -> { role, deviceId }
const devices = new Map();
const events = [];

function reply(res, code, data) {
  res.writeHead(code, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 100000) reject(new Error('body too large')); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch(e) { reject(e); } });
  });
}
function bearer(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  return tokens.get(h.slice(7)) || null;
}
function token() { return crypto.randomBytes(32).toString('hex'); }
function cleanPairs() {
  const now = Date.now();
  for (const [code, p] of pairs.entries()) if (p.expiresAt < now || p.used) pairs.delete(code);
}
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {'Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization'});
    return res.end();
  }
  if (req.url === '/health' && req.method === 'GET') return reply(res, 200, {ok:true, service:'guardian-api'});
  try {
    if (req.url === '/api/pair/start' && req.method === 'POST') {
      cleanPairs();
      let code;
      do { code = String(crypto.randomInt(100000, 1000000)); } while (pairs.has(code));
      const parentToken = token();
      pairs.set(code, {expiresAt:Date.now() + 10 * 60 * 1000, parentToken, used:false});
      tokens.set(parentToken, {role:'parent'});
      return reply(res, 201, {code, expiresInSeconds:600, parentToken});
    }
    if (req.url === '/api/pair/approve' && req.method === 'POST') {
      cleanPairs();
      const b = await readBody(req);
      const code = String(b.code || '');
      const p = pairs.get(code);
      if (!p || p.used || p.expiresAt < Date.now()) return reply(res, 400, {error:'invalid_or_expired_code'});
      if (!b.deviceId || String(b.deviceId).length > 100) return reply(res, 400, {error:'invalid_device_id'});
      p.used = true;
      const deviceId = String(b.deviceId);
      const childToken = token();
      tokens.set(childToken, {role:'child', deviceId});
      devices.set(deviceId, {deviceId, label:String(b.label || deviceId), enrolledAt:new Date().toISOString()});
      p.deviceId = deviceId;
      p.childToken = childToken;
      events.unshift({id:crypto.randomUUID(), type:'device_enrolled', deviceId, at:new Date().toISOString()});
      // Store association so parent can only view events for its paired device.
      tokens.set(p.parentToken, {role:'parent', deviceId});
      return reply(res, 201, {ok:true, childToken, deviceId});
    }
    const auth = bearer(req);
    if (!auth) return reply(res, 401, {error:'unauthorized'});
    if (req.url === '/api/sos' && req.method === 'POST') {
      if (auth.role !== 'child') return reply(res, 403, {error:'child_token_required'});
      const b = await readBody(req);
      const event = {id:crypto.randomUUID(), type:'sos', deviceId:auth.deviceId,
        message:String(b.message || 'SOS'), at:new Date().toISOString()};
      events.unshift(event);
      return reply(res, 201, {ok:true, eventId:event.id});
    }
    if (req.url === '/api/events' && req.method === 'GET') {
      if (auth.role !== 'parent') return reply(res, 403, {error:'parent_token_required'});
      const visible = events.filter(e => !auth.deviceId || e.deviceId === auth.deviceId).slice(0,100);
      return reply(res, 200, {events:visible});
    }
    if (req.url === '/api/devices' && req.method === 'GET') {
      if (auth.role !== 'parent') return reply(res, 403, {error:'parent_token_required'});
      const visible = [...devices.values()].filter(d => !auth.deviceId || d.deviceId === auth.deviceId);
      return reply(res, 200, {devices:visible});
    }
    return reply(res, 404, {error:'not_found'});
  } catch (e) { return reply(res, 400, {error:'invalid_request', detail:e.message}); }
});
server.listen(PORT, () => console.log('Guardian API listening on port ' + PORT));
