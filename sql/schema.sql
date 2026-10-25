CREATE TABLE IF NOT EXISTS families (
  id UUID PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('parent','kid')),
  label TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL UNIQUE,
  last_seen_at TIMESTAMPTZ,
  battery_percent INTEGER CHECK (battery_percent BETWEEN 0 AND 100),
  device_model TEXT NOT NULL DEFAULT '',
  android_version TEXT NOT NULL DEFAULT '',
  app_version TEXT NOT NULL DEFAULT '',
  app_state TEXT NOT NULL DEFAULT 'unknown',
  status_updated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS enroll_codes (
  code_hash TEXT PRIMARY KEY,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  parent_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS locations (
  device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  latitude DOUBLE PRECISION NOT NULL CHECK (latitude BETWEEN -90 AND 90),
  longitude DOUBLE PRECISION NOT NULL CHECK (longitude BETWEEN -180 AND 180),
  accuracy_m DOUBLE PRECISION,
  captured_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS commands (
  id UUID PRIMARY KEY,
  family_id UUID NOT NULL REFERENCES families(id) ON DELETE CASCADE,
  target_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_by_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('PIN_HASH_UPDATE')),
  payload JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  acknowledged_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS events_family_created_idx ON events(family_id, created_at DESC);
CREATE INDEX IF NOT EXISTS commands_target_status_idx ON commands(target_device_id, status, created_at);

-- Safe additive migration for databases created by earlier Guardian versions.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS battery_percent INTEGER CHECK (battery_percent BETWEEN 0 AND 100);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_model TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS android_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS app_version TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS app_state TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ;

