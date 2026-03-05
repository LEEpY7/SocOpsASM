'use strict'

const Database = require('better-sqlite3')
const path     = require('path')

const DB_PATH = path.join(__dirname, '../data/finmonitor.db')
const db = new Database(DB_PATH)

// WAL 모드 – 동시 읽기/쓰기 성능 향상
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

// ─── 스키마 생성 ─────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    url          TEXT NOT NULL UNIQUE,
    category     TEXT NOT NULL DEFAULT 'other',
    sub_category TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    interval_sec INTEGER NOT NULL DEFAULT 60,
    created_at   TEXT DEFAULT (datetime('now','localtime')),
    updated_at   TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS probe_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id        INTEGER NOT NULL,
    probe_time       TEXT    DEFAULT (datetime('now','localtime')),

    -- 기본 가용성
    probe_success    INTEGER,          -- 1=UP / 0=DOWN
    probe_failed     INTEGER,          -- 1=실패(네트워크 오류 등)

    -- HTTP 상세
    http_status_code INTEGER,
    http_version     TEXT,
    http_redirects   INTEGER,
    http_content_length INTEGER,
    http_duration_resolve_ms   REAL,
    http_duration_connect_ms   REAL,
    http_duration_tls_ms       REAL,
    http_duration_processing_ms REAL,
    http_duration_transfer_ms  REAL,

    -- 전체 응답시간
    probe_duration_ms REAL,

    -- TLS/SSL
    tls_version         TEXT,
    tls_cipher          TEXT,
    ssl_expiry_days     INTEGER,       -- 인증서 만료까지 남은 일수
    ssl_earliest_expiry TEXT,          -- 만료 일시 문자열

    -- DNS
    dns_lookup_ms REAL,

    -- 오류 메시지
    error_msg TEXT,

    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_probe_target_time
    ON probe_results(target_id, probe_time DESC);

  CREATE TABLE IF NOT EXISTS alert_configs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    to_email    TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    down_notify INTEGER NOT NULL DEFAULT 1,
    threshold_ms INTEGER NOT NULL DEFAULT 3000,
    ssl_warn_days INTEGER NOT NULL DEFAULT 30,
    created_at  TEXT DEFAULT (datetime('now','localtime'))
  );

  CREATE TABLE IF NOT EXISTS alert_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER,
    alert_config_id INTEGER,
    alert_type      TEXT,   -- 'down' | 'slow' | 'ssl_expiry'
    message         TEXT,
    sent_at         TEXT DEFAULT (datetime('now','localtime')),
    success         INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS alert_state (
    target_id    INTEGER PRIMARY KEY,
    is_alerting  INTEGER DEFAULT 0,
    alerted_at   TEXT
  );
`)

// ─── 시드: 초기 타겟이 없으면 한화생명 삽입 ───────────────────────
const cnt = db.prepare('SELECT COUNT(*) as c FROM targets').get()
if (cnt.c === 0) {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO targets (name, url, category, sub_category)
    VALUES (@name, @url, @category, @sub_category)
  `)
  const seeds = [
    { name: '한화생명', url: 'https://hanwhalife.com', category: 'insurance', sub_category: '생명보험' }
  ]
  const insertAll = db.transaction((rows) => rows.forEach(r => insert.run(r)))
  insertAll(seeds)
}

module.exports = db
