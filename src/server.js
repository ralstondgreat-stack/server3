'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '24kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined });
const PORT = Number(process.env.PORT || 3000);
const uuid = () => crypto.randomUUID();
const hash = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const token = () => crypto.randomBytes(32).toString('base64url');
const code = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
const asyncRoute = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);

async function ensureSchema() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'sql', 'schema.sql'), 'utf8');
  await pool.query(sql);
}
async function auth(req, res, next) {
  try {
    const raw = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    if (!raw) return res.status(401).json({ error: 'Bearer token required' });
    const result = await pool.query('SELECT id, family_id, role, label FROM devices WHERE token_hash=$1', [hash(raw)]);
    if (!result.rowCount) return res.status(401).json({ error: 'Invalid device token' });
    req.device = result.rows[0];
    await pool.query('UPDATE devices SET last_seen_at=NOW() WHERE id=$1', [req.device.id]);
    next();
  } catch (e) { next(e); }
}
function role(wanted) { return (req,res,next) => req.device.role === wanted ? next() : res.status(403).json({error:`${wanted} device required`}); }
async function event(familyId, deviceId, type, payload={}) {
  await pool.query('INSERT INTO events(family_id,device_id,type,payload) VALUES($1,$2,$3,$4)', [familyId,deviceId,type,payload]);
}

app.get('/', (_req,res) => res.json({ name:'Guardian API', status:'ok', api:'/api/health' }));
app.get('/api/health', asyncRoute(async (_req,res) => {
  await pool.query('SELECT 1'); res.json({ ok:true, service:'guardian-api', time:new Date().toISOString() });
}));

// Create a family and a parent device. Keep the returned token private.
app.post('/api/setup/parent', rateLimit({windowMs:60*60*1000, limit:10}), asyncRoute(async (req,res) => {
  const label = String(req.body?.label || 'Guardian phone').slice(0,80);
  const familyId = uuid(), deviceId = uuid(), rawToken = token();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO families(id) VALUES($1)',[familyId]);
    await client.query('INSERT INTO devices(id,family_id,role,label,token_hash) VALUES($1,$2,$3,$4,$5)',[deviceId,familyId,'parent',label,hash(rawToken)]);
    await client.query('COMMIT');
  } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  res.status(201).json({ familyId, deviceId, role:'parent', token:rawToken, warning:'Store this token securely. It cannot be retrieved later.' });
}));

app.post('/api/enrollment/code', auth, role('parent'), asyncRoute(async (req,res) => {
  const plain = code(), codeHash = hash(plain);
  await pool.query('INSERT INTO enroll_codes(code_hash,family_id,parent_device_id,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL \'10 minutes\')',[codeHash,req.device.family_id,req.device.id]);
  res.status(201).json({ code:plain, expiresInSeconds:600, instructions:'Enter this code in the KID app with the parent present.' });
}));

app.post('/api/enrollment/complete', rateLimit({windowMs:60_000,limit:10}), asyncRoute(async (req,res) => {
  const provided = String(req.body?.code || '').trim();
  const label = String(req.body?.label || 'KID device').slice(0,80);
  if (!/^\d{6}$/.test(provided)) return res.status(400).json({error:'A six-digit enrollment code is required'});
  const client = await pool.connect();
  const deviceId = uuid(), rawToken = token();
  try {
    await client.query('BEGIN');
    const c = await client.query('SELECT * FROM enroll_codes WHERE code_hash=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE',[hash(provided)]);
    if (!c.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({error:'Invalid or expired enrollment code'}); }
    const familyId = c.rows[0].family_id;
    await client.query('INSERT INTO devices(id,family_id,role,label,token_hash) VALUES($1,$2,$3,$4,$5)',[deviceId,familyId,'kid',label,hash(rawToken)]);
    await client.query('UPDATE enroll_codes SET used_at=NOW() WHERE code_hash=$1',[hash(provided)]);
    await client.query('COMMIT');
    await event(familyId,deviceId,'device_enrolled',{label});
    res.status(201).json({ familyId, deviceId, role:'kid', token:rawToken, warning:'Store this token securely. It cannot be retrieved later.' });
  } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}));

app.get('/api/device/status', auth, asyncRoute(async (req,res) => {
  const q = await pool.query('SELECT id,role,label,last_seen_at,created_at,battery_percent,device_model,android_version,app_version,app_state,status_updated_at FROM devices WHERE family_id=$1 ORDER BY created_at',[req.device.family_id]);
  res.json({ devices:q.rows.map(d=>({...d, online: d.last_seen_at && (Date.now()-new Date(d.last_seen_at).getTime()<120000)})) });
}));

// KID heartbeat: reports only basic device/app status, not location or personal content.
app.post('/api/device/heartbeat', auth, role('kid'), asyncRoute(async (req,res) => {
  const rawBattery=req.body?.batteryPercent;
  const battery=rawBattery===null || rawBattery===undefined || rawBattery==='' ? null : Number(rawBattery);
  if (battery!==null && (!Number.isInteger(battery) || battery<0 || battery>100)) return res.status(400).json({error:'batteryPercent must be an integer from 0 to 100, or null'});
  const deviceModel=String(req.body?.deviceModel||'').slice(0,160);
  const androidVersion=String(req.body?.androidVersion||'').slice(0,40);
  const appVersion=String(req.body?.appVersion||'').slice(0,40);
  const appState=['foreground','background','unknown'].includes(String(req.body?.appState||'')) ? String(req.body.appState) : 'unknown';
  await pool.query('UPDATE devices SET battery_percent=$2,device_model=$3,android_version=$4,app_version=$5,app_state=$6,status_updated_at=NOW(),last_seen_at=NOW() WHERE id=$1',[req.device.id,battery,deviceModel,androidVersion,appVersion,appState]);
  res.json({accepted:true,serverTime:new Date().toISOString()});
}));

app.post('/api/sos', auth, role('kid'), asyncRoute(async (req,res) => {
  const message = String(req.body?.message || 'SOS alert').slice(0,500);
  const location = req.body?.location;
  let safeLocation = null;
  if (location && Number.isFinite(Number(location.latitude)) && Number.isFinite(Number(location.longitude)) && Math.abs(Number(location.latitude))<=90 && Math.abs(Number(location.longitude))<=180) {
    safeLocation = {latitude:Number(location.latitude),longitude:Number(location.longitude),accuracyM:Number(location.accuracyM)||null};
  }
  await event(req.device.family_id,req.device.id,'sos',{message,location:safeLocation});
  res.status(202).json({ accepted:true, message:'SOS stored for Guardian to retrieve.' });
}));

app.post('/api/location', auth, role('kid'), asyncRoute(async (req,res) => {
  const lat=Number(req.body?.latitude), lon=Number(req.body?.longitude), accuracy=req.body?.accuracyM == null ? null : Number(req.body.accuracyM);
  if (!Number.isFinite(lat)||!Number.isFinite(lon)||Math.abs(lat)>90||Math.abs(lon)>180) return res.status(400).json({error:'Valid latitude and longitude are required'});
  const capturedAt = req.body?.capturedAt ? new Date(req.body.capturedAt) : new Date();
  if (Number.isNaN(capturedAt.getTime()) || capturedAt.getTime()>Date.now()+60000) return res.status(400).json({error:'Invalid capturedAt'});
  await pool.query(`INSERT INTO locations(device_id,family_id,latitude,longitude,accuracy_m,captured_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,NOW()) ON CONFLICT(device_id) DO UPDATE SET latitude=EXCLUDED.latitude,longitude=EXCLUDED.longitude,accuracy_m=EXCLUDED.accuracy_m,captured_at=EXCLUDED.captured_at,updated_at=NOW()`,[req.device.id,req.device.family_id,lat,lon,Number.isFinite(accuracy)?accuracy:null,capturedAt]);
  res.status(202).json({accepted:true});
}));
app.get('/api/location', auth, role('parent'), asyncRoute(async (req,res) => {
  const q=await pool.query(`SELECT l.device_id,l.latitude,l.longitude,l.accuracy_m,l.captured_at,l.updated_at,d.label FROM locations l JOIN devices d ON d.id=l.device_id WHERE l.family_id=$1 ORDER BY l.updated_at DESC`,[req.device.family_id]);
  res.json({locations:q.rows});
}));

app.get('/api/events', auth, role('parent'), asyncRoute(async (req,res) => {
  const limit=Math.max(1,Math.min(100,Number.parseInt(req.query.limit||'50',10)||50));
  const q=await pool.query('SELECT e.id,e.type,e.payload,e.created_at,d.label AS device_label FROM events e LEFT JOIN devices d ON d.id=e.device_id WHERE e.family_id=$1 ORDER BY e.created_at DESC LIMIT $2',[req.device.family_id,limit]);
  res.json({events:q.rows});
}));

// PIN updates carry only a salted scrypt verifier, never the raw PIN. Since a 4-digit PIN has a small search space,
// use it only as an app convenience lock and retain Android/device-level protections.
app.post('/api/pin/change', auth, role('parent'), asyncRoute(async (req,res) => {
  const targetId=String(req.body?.targetDeviceId||'');
  const salt=String(req.body?.salt||'');
  const verifier=String(req.body?.verifier||'');
  if (!targetId || !/^[a-f0-9]{32,128}$/i.test(salt) || !/^[a-f0-9]{64,256}$/i.test(verifier)) return res.status(400).json({error:'targetDeviceId, salt and verifier are required'});
  const target=await pool.query("SELECT id FROM devices WHERE id=$1 AND family_id=$2 AND role='kid'",[targetId,req.device.family_id]);
  if (!target.rowCount) return res.status(404).json({error:'KID device not found in this family'});
  const id=uuid();
  await pool.query("INSERT INTO commands(id,family_id,target_device_id,created_by_device_id,type,payload,expires_at) VALUES($1,$2,$3,$4,'PIN_HASH_UPDATE',$5,NOW()+INTERVAL '24 hours')",[id,req.device.family_id,targetId,req.device.id,{salt,verifier}]);
  await event(req.device.family_id,req.device.id,'pin_change_requested',{targetDeviceId:targetId,commandId:id});
  res.status(202).json({accepted:true,commandId:id,status:'pending'});
}));
app.get('/api/commands/pending', auth, role('kid'), asyncRoute(async (req,res) => {
  const q=await pool.query("SELECT id,type,payload,created_at,expires_at FROM commands WHERE target_device_id=$1 AND status='pending' AND expires_at>NOW() ORDER BY created_at LIMIT 20",[req.device.id]);
  res.json({commands:q.rows});
}));
app.post('/api/commands/:id/ack', auth, role('kid'), asyncRoute(async (req,res) => {
  const status=String(req.body?.status||'');
  if (!['applied','rejected'].includes(status)) return res.status(400).json({error:'status must be applied or rejected'});
  const q=await pool.query("UPDATE commands SET status=$1,acknowledged_at=NOW() WHERE id=$2 AND target_device_id=$3 AND status='pending' RETURNING id,type",[status,req.params.id,req.device.id]);
  if (!q.rowCount) return res.status(404).json({error:'Pending command not found'});
  await event(req.device.family_id,req.device.id,'command_acknowledged',{commandId:req.params.id,status});
  res.json({ok:true,status});
}));

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(500).json({error:'Internal server error'});
});
(async()=>{
  if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is required.'); process.exit(1); }
  await ensureSchema();
  app.listen(PORT,'0.0.0.0',()=>console.log(`Guardian API listening on ${PORT}`));
})().catch(e=>{console.error('Startup failed',e);process.exit(1)});
