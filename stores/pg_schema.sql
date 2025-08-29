CREATE TABLE IF NOT EXISTS document (
  id TEXT PRIMARY KEY,
  vendor TEXT,
  title TEXT,
  published_at DATE,
  tlp TEXT,
  sha256 TEXT UNIQUE,
  pages INT,
  namespace TEXT DEFAULT 'personal',
  ocr_pages INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS doc_chunk (
  id TEXT PRIMARY KEY,
  document_id TEXT REFERENCES document(id) ON DELETE CASCADE,
  page INT,
  bbox FLOAT8[],
  text TEXT,
  actors TEXT[],
  techniques TEXT[],
  cves TEXT[],
  confidence REAL,
  embed_model TEXT,
  embed_version TEXT,
  vector_dim INT,
  faiss_id BIGINT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS actor (
  id TEXT PRIMARY KEY,
  mitre_gid TEXT,
  names TEXT[]
);

CREATE TABLE IF NOT EXISTS technique (
  t_id TEXT PRIMARY KEY,
  name TEXT,
  parent_t_id TEXT,
  synonyms TEXT[]
);

CREATE TABLE IF NOT EXISTS cve (
  id TEXT PRIMARY KEY,
  cwe TEXT[],
  cvss NUMERIC,
  kev BOOLEAN,
  epss NUMERIC
);

CREATE TABLE IF NOT EXISTS actor_cve (
  actor_id TEXT REFERENCES actor(id),
  cve_id TEXT REFERENCES cve(id),
  weight REAL,
  PRIMARY KEY (actor_id, cve_id)
);

CREATE TABLE IF NOT EXISTS cve_technique (
  cve_id TEXT REFERENCES cve(id),
  t_id TEXT REFERENCES technique(t_id),
  weight REAL,
  source TEXT,
  PRIMARY KEY (cve_id, t_id)
);
