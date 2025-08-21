-- idempotent schema for SS360
CREATE TABLE IF NOT EXISTS scans (
  id BIGSERIAL PRIMARY KEY,
  repo_url TEXT NOT NULL,
  started_at TIMESTAMPTZ DEFAULT now(),
  finished_at TIMESTAMPTZ DEFAULT now(),
  duration_ms INTEGER DEFAULT 0,
  total_findings INT DEFAULT 0,
  true_hits INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  kind TEXT NOT NULL,
  match TEXT,
  is_secret BOOLEAN DEFAULT FALSE,
  reason TEXT
);

-- helpful indexes
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_is_secret ON findings(is_secret);
