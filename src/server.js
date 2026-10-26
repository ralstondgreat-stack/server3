'use strict';
require('dotenv').config();
const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '128kb' }));
app.use('/v1/', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: 'draft-7', legacyHeaders: false }));

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!process.env.ENROLLMENT_KEY) throw new Error('ENROLLMENT_KEY is required');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: true } : undefined,
  max: 10,
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000
});

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const safeEqual = (a, b) => {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
const makeCode = () => {
  // Excludes ambiguous characters. Code is still validated server-side and rate limited.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(8);
  return Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
};

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'kids-protection-api', version: '2.0.0', database: 'connected' });
  } catch (_e) {
    res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});

// Controlled test enrollment. In production, replace this shared enrollment key
// with real account sign-in / invitation-based enrollment before public release.
app.post('/v1/devices/register', async (req, res) => {
  const enrollmentKey = req.get('X-Enrollment-Key');
  if (!safeEqual(enrollmentKey, process.env.ENROLLMENT_KEY)) {
    return res.status(401).json({ error: 'invalid_enrollment_key' });
  }
  const role = req.body && req.body.role;
  const deviceName = String((req.body && req.body.deviceName) || 'Android device').trim().slice(0, 80);
  if (!['parent', 'child'].includes(role)) return res.status(400).json({ error: 'role_must_be_parent_or_child' });

  const token = crypto.randomBytes(32).toString('base64url');
  try {
    const result = await pool.query(
      'INSERT INTO devices(role, device_name, token_hash) VALUES($1,$2,$3) RETURNING id, role, device_name, created_at',
      [role, deviceName || 'Android device', sha256(token)]
    );
    res.status(201).json({ device: result.rows[0], deviceToken: token, tokenType: 'Bearer' });
  } catch (e) {
    console.error('device registration failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

async function authenticate(req, res, next) {
  const match = /^Bearer\s+(.+)$/i.exec(req.get('Authorization') || '');
  if (!match) return res.status(401).json({ error: 'missing_bearer_token' });
  try {
    const result = await pool.query(
      'SELECT id, role, device_name FROM devices WHERE token_hash=$1 AND revoked_at IS NULL',
      [sha256(match[1])]
    );
    if (!result.rowCount) return res.status(401).json({ error: 'invalid_or_revoked_token' });
    req.device = result.rows[0];
    next();
  } catch (e) {
    console.error('authentication failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
}
function requireRole(role) {
  return (req, res, next) => req.device.role === role
    ? next()
    : res.status(403).json({ error: 'wrong_device_role' });
}

// Mobile pairing flow: CHILD creates the code, PARENT enters and claims it.
// These endpoints intentionally match the current Android source paths.
app.post('/v1/pair/start', async (req, res) => {
  const deviceName = String((req.body && req.body.deviceName) || 'Child device').trim().slice(0, 80) || 'Child device';
  const suppliedId = String((req.body && req.body.deviceId) || '');
  const childId = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(suppliedId)
    ? suppliedId : crypto.randomUUID();
  const childToken = crypto.randomBytes(32).toString('base64url');

  try {
    const child = await pool.query(
      `INSERT INTO devices(id, role, device_name, token_hash)
       VALUES($1, 'child', $2, $3)
       ON CONFLICT (id) DO UPDATE
         SET device_name=EXCLUDED.device_name, token_hash=EXCLUDED.token_hash, revoked_at=NULL
         WHERE devices.role='child'
       RETURNING id, device_name`,
      [childId, deviceName, sha256(childToken)]
    );
    if (!child.rowCount) return res.status(409).json({ error: 'device_id_conflict' });

    for (let attempt = 0; attempt < 3; attempt++) {
      const code = makeCode();
      try {
        const created = await pool.query(
          `INSERT INTO pairing_codes(parent_device_id, child_device_id, code_hash, expires_at)
           VALUES(NULL, $1, $2, NOW() + INTERVAL '10 minutes')
           RETURNING id, expires_at`,
          [child.rows[0].id, sha256(code)]
        );
        return res.status(201).json({
          deviceId: child.rows[0].id,
          deviceName: child.rows[0].device_name,
          pairingCode: code,
          deviceToken: childToken,
          expiresAt: created.rows[0].expires_at,
          expiresInSeconds: 600
        });
      } catch (e) {
        if (e.code !== '23505') throw e;
      }
    }
    return res.status(503).json({ error: 'could_not_generate_code_retry' });
  } catch (e) {
    console.error('child pairing start failed', e.message);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/v1/pair/claim', async (req, res) => {
  const code = String((req.body && req.body.code) || '').trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{8}$/.test(code)) return res.status(400).json({ error: 'invalid_code_format' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      `SELECT pc.id, pc.child_device_id, d.device_name
       FROM pairing_codes pc
       JOIN devices d ON d.id=pc.child_device_id
       WHERE pc.code_hash=$1 AND pc.parent_device_id IS NULL
         AND pc.child_device_id IS NOT NULL AND pc.used_at IS NULL
         AND pc.expires_at > NOW() AND d.role='child' AND d.revoked_at IS NULL
       FOR UPDATE OF pc`,
      [sha256(code)]
    );
    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'invalid_expired_or_used_code' });
    }

    const child = found.rows[0];
    const parentToken = crypto.randomBytes(32).toString('base64url');
    const parentName = String((req.body && req.body.deviceName) || 'Parent device').trim().slice(0, 80) || 'Parent device';
    const parent = await client.query(
      `INSERT INTO devices(role, device_name, token_hash)
       VALUES('parent', $1, $2) RETURNING id`,
      [parentName, sha256(parentToken)]
    );
    const link = await client.query(
      `INSERT INTO parent_child_links(parent_device_id, child_device_id)
       VALUES($1, $2)
       ON CONFLICT(parent_device_id, child_device_id)
       DO UPDATE SET revoked_at=NULL, paired_at=NOW()
       RETURNING id, paired_at`,
      [parent.rows[0].id, child.child_device_id]
    );
    await client.query(
      'UPDATE pairing_codes SET parent_device_id=$2, used_at=NOW() WHERE id=$1',
      [child.id, parent.rows[0].id]
    );
    await client.query('COMMIT');
    return res.json({
      paired: true,
      pairingId: link.rows[0].id,
      pairedAt: link.rows[0].paired_at,
      deviceId: child.child_device_id,
      deviceName: child.device_name,
      parentToken,
      tokenType: 'Bearer'
    });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('parent pairing claim failed', e.message);
    return res.status(500).json({ error: 'internal_error' });
  } finally {
    client.release();
  }
});

app.post('/v1/pairing-codes', authenticate, requireRole('parent'), async (req, res) => {
  // Retry rare collisions without exposing stored code hashes.
  for (let attempt = 0; attempt < 3; attempt++) {
    const code = makeCode();
    try {
      const result = await pool.query(
        `INSERT INTO pairing_codes(parent_device_id, code_hash, expires_at)
         VALUES($1,$2,NOW() + INTERVAL '10 minutes')
         RETURNING id, expires_at`,
        [req.device.id, sha256(code)]
      );
      return res.status(201).json({ code, expiresAt: result.rows[0].expires_at, expiresInSeconds: 600 });
    } catch (e) {
      if (e.code !== '23505') {
        console.error('pairing code creation failed', e.message);
        return res.status(500).json({ error: 'internal_error' });
      }
    }
  }
  return res.status(503).json({ error: 'could_not_generate_code_retry' });
});

app.post('/v1/pairing/redeem', authenticate, requireRole('child'), async (req, res) => {
  const code = String((req.body && req.body.code) || '').trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{8}$/.test(code)) return res.status(400).json({ error: 'invalid_code_format' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Row lock + used_at check makes redemption single-use under concurrent requests.
    const found = await client.query(
      `SELECT id, parent_device_id FROM pairing_codes
       WHERE code_hash=$1 AND used_at IS NULL AND expires_at > NOW()
       FOR UPDATE`, [sha256(code)]
    );
    if (!found.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'invalid_expired_or_used_code' });
    }
    const pairing = found.rows[0];
    if (pairing.parent_device_id === req.device.id) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'cannot_pair_device_to_itself' });
    }
    const link = await client.query(
      `INSERT INTO parent_child_links(parent_device_id, child_device_id)
       VALUES($1,$2) ON CONFLICT(parent_device_id, child_device_id)
       DO UPDATE SET revoked_at=NULL RETURNING id, paired_at`,
      [pairing.parent_device_id, req.device.id]
    );
    await client.query(
      'UPDATE pairing_codes SET used_at=NOW(), child_device_id=$2 WHERE id=$1',
      [pairing.id, req.device.id]
    );
    await client.query('COMMIT');
    res.json({ paired: true, pairingId: link.rows[0].id, pairedAt: link.rows[0].paired_at });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('pairing redemption failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  } finally {
    client.release();
  }
});

// Child heartbeat. Only authenticated child devices can update their own presence.
app.post('/v1/heartbeat', authenticate, requireRole('child'), async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE devices SET last_seen_at=NOW()
       WHERE id=$1 AND role='child' AND revoked_at IS NULL
       RETURNING last_seen_at`, [req.device.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'child_device_not_found' });
    res.json({ ok: true, deviceId: req.device.id, lastSeenAt: result.rows[0].last_seen_at });
  } catch (e) {
    console.error('heartbeat failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/v1/children', authenticate, requireRole('parent'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT l.id AS pairing_id, l.paired_at, d.id AS child_device_id,
              d.device_name, d.created_at AS registered_at, d.last_seen_at,
              (d.last_seen_at IS NOT NULL AND d.last_seen_at >= NOW() - INTERVAL '90 seconds') AS online
       FROM parent_child_links l JOIN devices d ON d.id=l.child_device_id
       WHERE l.parent_device_id=$1 AND l.revoked_at IS NULL
       ORDER BY l.paired_at DESC`, [req.device.id]
    );
    res.json({ children: result.rows });
  } catch (e) {
    console.error('children query failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/v1/pairings/:pairingId/revoke', authenticate, requireRole('parent'), async (req, res) => {
  const { pairingId } = req.params;
  if (!/^[0-9a-f-]{36}$/i.test(pairingId)) return res.status(400).json({ error: 'invalid_pairing_id' });
  try {
    const result = await pool.query(
      `UPDATE parent_child_links SET revoked_at=NOW()
       WHERE id=$1 AND parent_device_id=$2 AND revoked_at IS NULL RETURNING id`,
      [pairingId, req.device.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'pairing_not_found' });
    res.json({ revoked: true });
  } catch (e) {
    console.error('pairing revoke failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

// V2.0 location and screen-time APIs. Data is accepted only from an authenticated
// child with an active parent link; parents can read only their own linked child.
async function childHasActiveParent(childId) {
  const result = await pool.query(
    'SELECT 1 FROM parent_child_links WHERE child_device_id=$1 AND revoked_at IS NULL LIMIT 1',
    [childId]
  );
  return result.rowCount > 0;
}
async function parentCanReadChild(parentId, childId) {
  const result = await pool.query(
    'SELECT 1 FROM parent_child_links WHERE parent_device_id=$1 AND child_device_id=$2 AND revoked_at IS NULL LIMIT 1',
    [parentId, childId]
  );
  return result.rowCount > 0;
}

app.post('/v1/location', authenticate, requireRole('child'), async (req, res) => {
  const latitude = Number(req.body && req.body.latitude);
  const longitude = Number(req.body && req.body.longitude);
  const accuracy = Number(req.body && req.body.accuracyMeters);
  const capturedAt = req.body && req.body.capturedAt ? new Date(req.body.capturedAt) : new Date();
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
      !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
      !Number.isFinite(accuracy) || accuracy < 0 || accuracy > 100000 ||
      Number.isNaN(capturedAt.getTime()) || Math.abs(Date.now() - capturedAt.getTime()) > 24 * 60 * 60 * 1000) {
    return res.status(400).json({ error: 'invalid_location_payload' });
  }
  try {
    if (!(await childHasActiveParent(req.device.id))) return res.status(409).json({ error: 'child_not_paired' });
    const result = await pool.query(
      `INSERT INTO child_locations(child_device_id, latitude, longitude, accuracy_meters, captured_at, received_at)
       VALUES($1,$2,$3,$4,$5,NOW())
       ON CONFLICT(child_device_id) DO UPDATE SET latitude=EXCLUDED.latitude,
         longitude=EXCLUDED.longitude, accuracy_meters=EXCLUDED.accuracy_meters,
         captured_at=EXCLUDED.captured_at, received_at=NOW()
       RETURNING captured_at, received_at`,
      [req.device.id, latitude, longitude, accuracy, capturedAt.toISOString()]
    );
    await pool.query('UPDATE devices SET last_seen_at=NOW() WHERE id=$1', [req.device.id]);
    res.json({ ok: true, capturedAt: result.rows[0].captured_at, receivedAt: result.rows[0].received_at });
  } catch (e) {
    console.error('location update failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/v1/children/:childId/location', authenticate, requireRole('parent'), async (req, res) => {
  const childId = req.params.childId;
  if (!/^[0-9a-f-]{36}$/i.test(childId)) return res.status(400).json({ error: 'invalid_child_id' });
  try {
    if (!(await parentCanReadChild(req.device.id, childId))) return res.status(404).json({ error: 'child_not_found' });
    const result = await pool.query(
      `SELECT latitude, longitude, accuracy_meters, captured_at, received_at
       FROM child_locations WHERE child_device_id=$1`, [childId]
    );
    res.json({ location: result.rows[0] || null });
  } catch (e) {
    console.error('location read failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/v1/screen-time/sync', authenticate, requireRole('child'), async (req, res) => {
  const usageDate = String((req.body && req.body.date) || '');
  const records = req.body && req.body.apps;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(usageDate) || !Array.isArray(records) || records.length > 250) {
    return res.status(400).json({ error: 'invalid_screen_time_payload' });
  }
  const validDate = new Date(`${usageDate}T00:00:00.000Z`);
  if (Number.isNaN(validDate.getTime()) || validDate.toISOString().slice(0, 10) !== usageDate) {
    return res.status(400).json({ error: 'invalid_usage_date' });
  }
  for (const appRecord of records) {
    if (!appRecord || typeof appRecord.packageName !== 'string' || appRecord.packageName.length > 200 ||
        typeof appRecord.appLabel !== 'string' || appRecord.appLabel.length > 120 ||
        !Number.isSafeInteger(appRecord.usageMs) || appRecord.usageMs < 0 || appRecord.usageMs > 86400000) {
      return res.status(400).json({ error: 'invalid_app_usage_record' });
    }
  }
  try {
    if (!(await childHasActiveParent(req.device.id))) return res.status(409).json({ error: 'child_not_paired' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM screen_time_usage WHERE child_device_id=$1 AND usage_date=$2', [req.device.id, usageDate]);
      for (const record of records) {
        if (record.usageMs === 0) continue;
        await client.query(
          `INSERT INTO screen_time_usage(child_device_id, usage_date, package_name, app_label, usage_ms, updated_at)
           VALUES($1,$2,$3,$4,$5,NOW())
           ON CONFLICT(child_device_id, usage_date, package_name) DO UPDATE SET
             app_label=EXCLUDED.app_label, usage_ms=EXCLUDED.usage_ms, updated_at=NOW()`,
          [req.device.id, usageDate, record.packageName, record.appLabel, record.usageMs]
        );
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
    finally { client.release(); }
    res.json({ ok: true, date: usageDate, appCount: records.filter(r => r.usageMs > 0).length });
  } catch (e) {
    console.error('screen-time sync failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.get('/v1/children/:childId/screen-time', authenticate, requireRole('parent'), async (req, res) => {
  const childId = req.params.childId;
  const date = String(req.query.date || new Date().toISOString().slice(0, 10));
  if (!/^[0-9a-f-]{36}$/i.test(childId)) return res.status(400).json({ error: 'invalid_child_id' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'invalid_usage_date' });
  try {
    if (!(await parentCanReadChild(req.device.id, childId))) return res.status(404).json({ error: 'child_not_found' });
    const result = await pool.query(
      `SELECT package_name, app_label, usage_ms, updated_at FROM screen_time_usage
       WHERE child_device_id=$1 AND usage_date=$2 ORDER BY usage_ms DESC, app_label ASC LIMIT 250`,
      [childId, date]
    );
    const totalUsageMs = result.rows.reduce((sum, row) => sum + Number(row.usage_ms), 0);
    res.json({ date, totalUsageMs, apps: result.rows });
  } catch (e) {
    console.error('screen-time read failed', e.message);
    res.status(500).json({ error: 'internal_error' });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && 'body' in err) return res.status(400).json({ error: 'invalid_json' });
  console.error('unhandled request error', err.message);
  return res.status(500).json({ error: 'internal_error' });
});

const port = Number(process.env.PORT || 3000);
let server;
async function ensureDatabaseSchema() {
  // Create tables before running ALTER TABLE. Some Render databases were deployed
  // without running db/schema.sql, which caused startup to fail with
  // relation \"pairing_codes\" does not exist.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS devices (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      role TEXT NOT NULL CHECK (role IN ('parent', 'child')),
      device_name TEXT NOT NULL DEFAULT 'Android device',
      token_hash CHAR(64) NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ,
      last_seen_at TIMESTAMPTZ
    )
  `);
  await pool.query('ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS pairing_codes (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      parent_device_id UUID REFERENCES devices(id),
      code_hash CHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      child_device_id UUID REFERENCES devices(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Add columns needed by child-first pairing when upgrading older installations.
  await pool.query('ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS child_device_id UUID REFERENCES devices(id)');
  await pool.query('ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE pairing_codes ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
  await pool.query('ALTER TABLE pairing_codes ALTER COLUMN parent_device_id DROP NOT NULL');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS parent_child_links (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      parent_device_id UUID NOT NULL REFERENCES devices(id),
      child_device_id UUID NOT NULL REFERENCES devices(id),
      paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      revoked_at TIMESTAMPTZ,
      UNIQUE(parent_device_id, child_device_id)
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS pairing_codes_parent_created_idx ON pairing_codes(parent_device_id, created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS pairing_codes_expiry_idx ON pairing_codes(expires_at)');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS child_locations (
      child_device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
      latitude DOUBLE PRECISION NOT NULL CHECK(latitude BETWEEN -90 AND 90),
      longitude DOUBLE PRECISION NOT NULL CHECK(longitude BETWEEN -180 AND 180),
      accuracy_meters DOUBLE PRECISION NOT NULL CHECK(accuracy_meters >= 0),
      captured_at TIMESTAMPTZ NOT NULL,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS screen_time_usage (
      child_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      usage_date DATE NOT NULL,
      package_name TEXT NOT NULL,
      app_label TEXT NOT NULL,
      usage_ms BIGINT NOT NULL CHECK(usage_ms >= 0 AND usage_ms <= 86400000),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(child_device_id, usage_date, package_name)
    )
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS screen_time_usage_child_date_idx ON screen_time_usage(child_device_id, usage_date)');
}

async function startServer() {
  await ensureDatabaseSchema();
  server = app.listen(port, '0.0.0.0', () => console.log(`Kids Protection API v2.0.0 listening on ${port}`));
}
startServer().catch(async e => {
  console.error('Server startup/migration failed:', e.message);
  await pool.end();
  process.exit(1);
});
async function shutdown() {
  if (!server) { await pool.end(); process.exit(0); return; }
  server.close(async () => { await pool.end(); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
