-- Add alias table for tracking actor alias provenance
-- Run with: psql "$PG_DSN" -f stores/migrations/2025_08_29_add_alias.sql

CREATE TABLE IF NOT EXISTS alias (
  actor_id TEXT REFERENCES actor(id),
  name TEXT,
  source TEXT,                -- 'seed' | 'rag_llm'
  provenance JSONB,           -- {doc_id,page,bbox,snippet_hash,model,run_id}
  confidence REAL,            -- 0..1
  created_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (actor_id, name)
);

-- Index for fast alias lookups
CREATE INDEX IF NOT EXISTS idx_alias_actor_id ON alias(actor_id);
CREATE INDEX IF NOT EXISTS idx_alias_name ON alias(name);
CREATE INDEX IF NOT EXISTS idx_alias_source ON alias(source);
CREATE INDEX IF NOT EXISTS idx_alias_confidence ON alias(confidence);

-- Add some example seed data (optional)
-- These would normally come from ATT&CK/MISP sync
INSERT INTO alias (actor_id, name, source, confidence) VALUES
('fin7', 'FIN7', 'seed', 1.0),
('fin7', 'Carbanak', 'seed', 1.0),
('fin7', 'Anunak', 'seed', 1.0),
('apt29', 'APT29', 'seed', 1.0),
('apt29', 'Cozy Bear', 'seed', 1.0),
('apt28', 'APT28', 'seed', 1.0),
('apt28', 'Fancy Bear', 'seed', 1.0),
('apt28', 'Sofacy', 'seed', 1.0)
ON CONFLICT (actor_id, name) DO NOTHING;
