'use strict'
/**
 * ASM (Attack Surface Management) DB 모듈
 * PostgreSQL (pg-native 호환 래퍼) 기반
 *
 * 레이어 구조:
 *   ① Raw Zone      — 툴 출력 원문 보존 (raw_*)
 *   ② Normalized    — 정규화된 자산/서비스/취약점 (asset, network_service, ...)
 *   ③ Current State — 현재 상태 뷰 (asset_current, service_current, ...)
 *   ④ Snapshot      — 일 단위 스냅샷 (asset_snapshot, ...)
 *   ⑤ Change Log    — 변화 감지 기록 (asset_change_log)
 */

const Database = require('./pg-compat')

const asmDb = new Database()

asmDb.pragma('journal_mode = WAL')
asmDb.pragma('foreign_keys = ON')

// ════════════════════════════════════════════════════════════════
//  RAW ZONE — 툴 출력 원문 보존
// ════════════════════════════════════════════════════════════════
asmDb.exec(`

  -- ── Scan Job (스캔 작업 관리) ──────────────────────────────
  CREATE TABLE IF NOT EXISTS scan_job (
    id           BIGSERIAL PRIMARY KEY,
    job_name     TEXT,
    tool         TEXT NOT NULL,   -- amass|subfinder|dnsx|naabu|masscan|nmap|httpx|nuclei
    target_scope TEXT,            -- 스캔 대상 (IP대역 or 도메인)
    status       TEXT NOT NULL DEFAULT 'pending',
                                  -- pending|running|done|failed
    started_at   TEXT,
    finished_at  TEXT,
    error_msg    TEXT,
    result_count INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  -- ── Raw: Amass ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_amass (
    id         BIGSERIAL PRIMARY KEY,
    job_id     INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    fqdn       TEXT,
    root_domain TEXT,
    record_type TEXT,   -- A|AAAA|CNAME|NS|MX|PTR
    answer     TEXT,    -- IP 또는 CNAME 값
    source     TEXT,    -- 발견 출처 (Certificate/DNS/Scraping...)
    asn        TEXT,
    cidr       TEXT,
    org        TEXT,
    cdn        TEXT,
    raw_json   TEXT,    -- 원본 JSON
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_amass_fqdn ON raw_amass(fqdn);

  -- ── Raw: Subfinder ─────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_subfinder (
    id         BIGSERIAL PRIMARY KEY,
    job_id     INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    fqdn       TEXT,
    root_domain TEXT,
    source     TEXT,
    raw_line   TEXT,
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_subfinder_fqdn ON raw_subfinder(fqdn);

  -- ── Raw: dnsx ──────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_dnsx (
    id         BIGSERIAL PRIMARY KEY,
    job_id     INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    fqdn       TEXT,
    record_type TEXT,
    answer     TEXT,
    status_code TEXT,  -- NOERROR|NXDOMAIN|SERVFAIL
    raw_json   TEXT,
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_dnsx_fqdn ON raw_dnsx(fqdn);

  -- ── Raw: Naabu (포트스캔) ──────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_naabu (
    id         BIGSERIAL PRIMARY KEY,
    job_id     INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    ip         TEXT,
    port       INTEGER,
    protocol   TEXT DEFAULT 'tcp',
    raw_line   TEXT,
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_naabu_ip ON raw_naabu(ip);

  -- ── Raw: Masscan ───────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_masscan (
    id         BIGSERIAL PRIMARY KEY,
    job_id     INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    ip         TEXT,
    port       INTEGER,
    protocol   TEXT DEFAULT 'tcp',
    ttl        INTEGER,
    reason     TEXT,
    raw_json   TEXT,
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_masscan_ip ON raw_masscan(ip);

  -- ── Raw: Nmap ──────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_nmap (
    id           BIGSERIAL PRIMARY KEY,
    job_id       INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    ip           TEXT,
    port         INTEGER,
    protocol     TEXT DEFAULT 'tcp',
    state        TEXT,   -- open|closed|filtered
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    extra_info   TEXT,
    os_name      TEXT,
    os_accuracy  INTEGER,
    cpe          TEXT,
    script_output TEXT,  -- NSE 스크립트 결과
    raw_xml      TEXT,
    collected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_nmap_ip_port ON raw_nmap(ip, port);

  -- ── Raw: httpx ─────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_httpx (
    id              BIGSERIAL PRIMARY KEY,
    job_id          INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    url             TEXT,
    fqdn            TEXT,
    ip              TEXT,
    port            INTEGER,
    status_code     INTEGER,
    title           TEXT,
    web_server      TEXT,
    content_length  INTEGER,
    content_type    TEXT,
    technology      TEXT,  -- JSON 배열: ["nginx","jQuery","Bootstrap"]
    jarm            TEXT,
    tls_version     TEXT,
    tls_cipher      TEXT,
    response_time_ms INTEGER,
    redirect_chain  TEXT,  -- JSON 배열
    favicon_hash    TEXT,
    raw_json        TEXT,
    collected_at    TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_httpx_url  ON raw_httpx(url);
  CREATE INDEX IF NOT EXISTS idx_raw_httpx_fqdn ON raw_httpx(fqdn);

  -- ── Raw: Nuclei (취약점) ───────────────────────────────────
  CREATE TABLE IF NOT EXISTS raw_nuclei (
    id               BIGSERIAL PRIMARY KEY,
    job_id           INTEGER REFERENCES scan_job(id) ON DELETE SET NULL,
    template_id      TEXT,
    template_name    TEXT,
    template_path    TEXT,
    severity         TEXT,  -- critical|high|medium|low|info|unknown
    cvss_score       REAL,
    cve_id           TEXT,
    cwe_id           TEXT,
    tags             TEXT,
    target_url       TEXT,
    target_ip        TEXT,
    target_fqdn      TEXT,
    target_port      INTEGER,
    matched_at       TEXT,   -- 매칭된 최종 URL/값
    extracted_results TEXT,  -- JSON 배열
    curl_command     TEXT,
    request          TEXT,
    response         TEXT,
    raw_json         TEXT,
    collected_at     TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_raw_nuclei_severity ON raw_nuclei(severity);
  CREATE INDEX IF NOT EXISTS idx_raw_nuclei_cve      ON raw_nuclei(cve_id);
  CREATE INDEX IF NOT EXISTS idx_raw_nuclei_target   ON raw_nuclei(target_ip, target_fqdn);

`)

// ════════════════════════════════════════════════════════════════
//  NORMALIZED ZONE — 정규화된 자산 데이터
// ════════════════════════════════════════════════════════════════
asmDb.exec(`

  -- ── Asset (IP 기반 자산 마스터) ────────────────────────────
  CREATE TABLE IF NOT EXISTS asset (
    id           BIGSERIAL PRIMARY KEY,
    ip           TEXT UNIQUE NOT NULL,   -- 대표 IP (인벤토리 기준 축)
    ip_version   INTEGER DEFAULT 4,      -- 4|6
    is_internal  INTEGER DEFAULT 0,      -- 내부망 여부
    is_exposed   INTEGER DEFAULT 1,      -- 외부 노출 여부
    asn          TEXT,
    cidr         TEXT,
    org          TEXT,
    cdn          TEXT,                   -- CDN 벤더명 (Cloudflare/Akamai 등)
    country_code TEXT,
    os_name      TEXT,                   -- Nmap OS 핑거프린트
    os_version   TEXT,
    risk_score   REAL DEFAULT 0,         -- 위험도 점수 (0~100, 취약점 집계 계산)
    first_seen   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen    TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    status       TEXT DEFAULT 'active'   -- active|inactive|archived
  );
  CREATE INDEX IF NOT EXISTS idx_asset_ip ON asset(ip);

  -- ── Asset Name (IP ↔ FQDN 매핑, N:M) ──────────────────────
  CREATE TABLE IF NOT EXISTS asset_name (
    id          BIGSERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    fqdn        TEXT NOT NULL,
    root_domain TEXT,
    record_type TEXT DEFAULT 'A',   -- A|AAAA|CNAME|PTR
    source      TEXT,               -- amass|subfinder|dnsx|manual
    first_seen  TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    UNIQUE(asset_id, fqdn)
  );
  CREATE INDEX IF NOT EXISTS idx_asset_name_fqdn     ON asset_name(fqdn);
  CREATE INDEX IF NOT EXISTS idx_asset_name_asset_id ON asset_name(asset_id);
  CREATE INDEX IF NOT EXISTS idx_asset_name_root     ON asset_name(root_domain);

  -- ── DNS Record (DNS 레코드 상세) ───────────────────────────
  CREATE TABLE IF NOT EXISTS dns_record (
    id          BIGSERIAL PRIMARY KEY,
    fqdn        TEXT NOT NULL,
    record_type TEXT NOT NULL,   -- A|AAAA|CNAME|NS|MX|TXT|PTR
    value       TEXT NOT NULL,
    ttl         INTEGER,
    source      TEXT,
    first_seen  TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    UNIQUE(fqdn, record_type, value)
  );
  CREATE INDEX IF NOT EXISTS idx_dns_record_fqdn ON dns_record(fqdn);

  -- ── Network Service (포트/서비스 정보) ─────────────────────
  --    Naabu/Masscan → 포트 존재 확인
  --    Nmap → service_name/product/version (우선 신뢰)
  CREATE TABLE IF NOT EXISTS network_service (
    id           BIGSERIAL PRIMARY KEY,
    asset_id     INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    ip           TEXT NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'tcp',  -- tcp|udp
    state        TEXT NOT NULL DEFAULT 'open',  -- open|filtered|closed
    service_name TEXT,   -- http|https|ssh|ftp|smtp...
    product      TEXT,   -- nginx|Apache|OpenSSH...
    version      TEXT,   -- 1.2.3
    extra_info   TEXT,
    cpe          TEXT,
    banner       TEXT,
    fingerprint_source TEXT DEFAULT 'nmap',  -- nmap|naabu|masscan|httpx
    first_seen   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen    TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    UNIQUE(ip, port, protocol)
  );
  CREATE INDEX IF NOT EXISTS idx_network_service_asset ON network_service(asset_id);
  CREATE INDEX IF NOT EXISTS idx_network_service_port  ON network_service(port);

  -- ── HTTP Endpoint (웹 서비스 정보) ─────────────────────────
  CREATE TABLE IF NOT EXISTS http_endpoint (
    id              BIGSERIAL PRIMARY KEY,
    asset_id        INTEGER REFERENCES asset(id) ON DELETE CASCADE,
    url             TEXT NOT NULL UNIQUE,
    fqdn            TEXT,
    ip              TEXT,
    port            INTEGER,
    scheme          TEXT DEFAULT 'https',
    status_code     INTEGER,
    title           TEXT,
    web_server      TEXT,
    content_length  INTEGER,
    content_type    TEXT,
    technology      TEXT,   -- JSON 배열
    jarm            TEXT,
    tls_version     TEXT,
    tls_cipher      TEXT,
    response_time_ms INTEGER,
    redirect_url    TEXT,
    favicon_hash    TEXT,
    first_seen      TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen       TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_http_endpoint_asset ON http_endpoint(asset_id);
  CREATE INDEX IF NOT EXISTS idx_http_endpoint_fqdn  ON http_endpoint(fqdn);

  -- ── Vulnerability Finding (취약점) ─────────────────────────
  CREATE TABLE IF NOT EXISTS vulnerability_finding (
    id               BIGSERIAL PRIMARY KEY,
    asset_id         INTEGER REFERENCES asset(id) ON DELETE CASCADE,
    ip               TEXT,
    fqdn             TEXT,
    url              TEXT,
    port             INTEGER,
    service_name     TEXT,
    template_id      TEXT NOT NULL,
    template_name    TEXT,
    severity         TEXT NOT NULL DEFAULT 'info',
    cvss_score       REAL,
    cve_id           TEXT,
    cwe_id           TEXT,
    tags             TEXT,
    matched_at       TEXT,
    extracted_results TEXT,
    status           TEXT DEFAULT 'open',  -- open|acknowledged|fixed|false_positive
    first_seen       TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    last_seen        TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_vuln_asset    ON vulnerability_finding(asset_id);
  CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerability_finding(severity);
  CREATE INDEX IF NOT EXISTS idx_vuln_cve      ON vulnerability_finding(cve_id);
  CREATE INDEX IF NOT EXISTS idx_vuln_status   ON vulnerability_finding(status);

`)

// ════════════════════════════════════════════════════════════════
//  SNAPSHOT & CURRENT STATE
// ════════════════════════════════════════════════════════════════
asmDb.exec(`

  -- asset_current : asset JOIN asset_name 집계 뷰 (매일 갱신)
  CREATE TABLE IF NOT EXISTS asset_current (
    ip              TEXT PRIMARY KEY,
    asset_id        INTEGER,
    fqdns           TEXT,   -- JSON 배열: ["a.com","b.a.com"]
    root_domains    TEXT,   -- JSON 배열: 중복 제거
    is_exposed      INTEGER,
    is_internal     INTEGER,
    asn             TEXT,
    cdn             TEXT,
    os_name         TEXT,
    open_ports      TEXT,   -- JSON 배열: [80,443,22]
    service_summary TEXT,   -- JSON: {80:"http/nginx 1.24",443:"https/nginx 1.24"}
    web_titles      TEXT,   -- JSON: ["Title A","Title B"]
    technologies    TEXT,   -- JSON 배열 (중복제거)
    risk_score      REAL,
    vuln_critical   INTEGER DEFAULT 0,
    vuln_high       INTEGER DEFAULT 0,
    vuln_medium     INTEGER DEFAULT 0,
    vuln_low        INTEGER DEFAULT 0,
    vuln_info       INTEGER DEFAULT 0,
    first_seen      TEXT,
    last_seen       TEXT,
    status          TEXT
  );

  -- service_current
  CREATE TABLE IF NOT EXISTS service_current (
    ip           TEXT NOT NULL,
    port         INTEGER NOT NULL,
    protocol     TEXT NOT NULL DEFAULT 'tcp',
    state        TEXT,
    service_name TEXT,
    product      TEXT,
    version      TEXT,
    last_seen    TEXT,
    PRIMARY KEY(ip, port, protocol)
  );

  -- http_current
  CREATE TABLE IF NOT EXISTS http_current (
    url             TEXT PRIMARY KEY,
    ip              TEXT,
    fqdn            TEXT,
    port            INTEGER,
    status_code     INTEGER,
    title           TEXT,
    web_server      TEXT,
    technology      TEXT,
    jarm            TEXT,
    tls_version     TEXT,
    response_time_ms INTEGER,
    last_seen       TEXT
  );

  -- vuln_current
  CREATE TABLE IF NOT EXISTS vuln_current (
    id           INTEGER PRIMARY KEY,
    ip           TEXT,
    fqdn         TEXT,
    url          TEXT,
    port         INTEGER,
    service_name TEXT,
    template_id  TEXT,
    template_name TEXT,
    severity     TEXT,
    cvss_score   REAL,
    cve_id       TEXT,
    status       TEXT,
    first_seen   TEXT,
    last_seen    TEXT
  );

  -- ── Snapshot 테이블 ─────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS asset_snapshot (
    id         BIGSERIAL PRIMARY KEY,
    snap_date  TEXT NOT NULL,   -- YYYY-MM-DD
    ip         TEXT NOT NULL,
    data_json  TEXT NOT NULL,   -- asset_current 행 전체 JSON
    UNIQUE(snap_date, ip)
  );
  CREATE INDEX IF NOT EXISTS idx_asset_snap_date ON asset_snapshot(snap_date);

  CREATE TABLE IF NOT EXISTS vuln_snapshot (
    id            BIGSERIAL PRIMARY KEY,
    snap_date     TEXT NOT NULL,
    ip            TEXT,
    template_id   TEXT,
    severity      TEXT,
    count         INTEGER DEFAULT 0,
    UNIQUE(snap_date, ip, template_id)
  );
  CREATE INDEX IF NOT EXISTS idx_vuln_snap_date ON vuln_snapshot(snap_date);

  -- ── Change Log ──────────────────────────────────────────────
  CREATE TABLE IF NOT EXISTS asset_change_log (
    id          BIGSERIAL PRIMARY KEY,
    change_type TEXT NOT NULL,
    -- new_asset|new_port|port_closed|version_change|new_vuln|vuln_fixed|new_fqdn
    asset_ip    TEXT,
    asset_id    INTEGER,
    detail      TEXT,   -- 변경 상세 JSON
    severity    TEXT DEFAULT 'info',  -- critical|high|medium|low|info
    detected_at TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );
  CREATE INDEX IF NOT EXISTS idx_change_log_type    ON asset_change_log(change_type);
  CREATE INDEX IF NOT EXISTS idx_change_log_ip      ON asset_change_log(asset_ip);
  CREATE INDEX IF NOT EXISTS idx_change_log_time    ON asset_change_log(detected_at DESC);

`)

// ════════════════════════════════════════════════════════════════
//  SCAN TARGET — 사용자가 등록한 스캔 대상 (IP대역/도메인)
// ════════════════════════════════════════════════════════════════
asmDb.exec(`
  -- 스캔 대상 등록 테이블
  CREATE TABLE IF NOT EXISTS scan_target (
    id           BIGSERIAL PRIMARY KEY,
    type         TEXT NOT NULL,        -- 'ip_range' | 'domain'
    value        TEXT NOT NULL UNIQUE, -- 192.168.1.0/24 | hanwhalife.com
    label        TEXT,                 -- 사람이 읽기 쉬운 이름
    description  TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    updated_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  -- 파이프라인 실행 세션 (1회 전체 스캔 = 1 pipeline_run)
  CREATE TABLE IF NOT EXISTS pipeline_run (
    id           BIGSERIAL PRIMARY KEY,
    status       TEXT NOT NULL DEFAULT 'pending',
    -- pending | running | done | failed | cancelled
    triggered_by TEXT DEFAULT 'manual',  -- manual | schedule
    started_at   TEXT,
    finished_at  TEXT,
    total_stages INTEGER DEFAULT 7,
    done_stages  INTEGER DEFAULT 0,
    current_stage TEXT,  -- amass|subfinder|dnsx|naabu|masscan|nmap|httpx|nuclei
    summary_json TEXT,   -- { new_assets, new_services, new_vulns, ... }
    error_msg    TEXT,
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  -- 파이프라인 단계별 로그
  CREATE TABLE IF NOT EXISTS pipeline_stage_log (
    id           BIGSERIAL PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES pipeline_run(id) ON DELETE CASCADE,
    stage        TEXT NOT NULL,  -- amass|subfinder|dnsx|naabu|masscan|nmap|httpx|nuclei
    status       TEXT DEFAULT 'pending', -- pending|running|done|failed|skipped
    started_at   TEXT,
    finished_at  TEXT,
    result_count INTEGER DEFAULT 0,
    command_line TEXT,  -- 실제 실행된 명령줄 (디버깅용)
    stdout_tail  TEXT,  -- 마지막 200자
    error_msg    TEXT
  );
`)

// scan_target 시드 — 한화생명 예시
;(function seedScanTargets() {
  const cnt = asmDb.prepare('SELECT COUNT(*) AS c FROM scan_target').get()
  if (cnt.c > 0) return
  const ins = asmDb.prepare(`
    INSERT INTO scan_target (type, value, label, description)
    VALUES (@type, @value, @label, @description)
    ON CONFLICT DO NOTHING
  `)
  const seeds = [
    { type:'ip_range', value:'211.234.10.0/24', label:'한화생명 공인 IP 대역 A', description:'DMZ 서버팜' },
    { type:'ip_range', value:'203.0.113.0/24',  label:'CDN/외부 IP 대역',       description:'Cloudflare 경유' },
    { type:'domain',   value:'hanwhalife.com',   label:'한화생명 대표 도메인',   description:'메인 사이트 + 서브도메인 전체' },
  ]
  asmDb.transaction(rows => rows.forEach(r => ins.run(r)))(seeds)
  console.log('[ASM-DB] scan_target 시드 3건 삽입 완료')
})()

// ════════════════════════════════════════════════════════════════
//  시드 데이터 — 한화생명 ASM 샘플
// ════════════════════════════════════════════════════════════════
;(function seedAsmData() {
  const cnt = asmDb.prepare('SELECT COUNT(*) AS c FROM asset').get()
  if (cnt.c > 0) return

  console.log('[ASM-DB] 시드 데이터 주입 시작')

  // ① 자산 시드
  const insertAsset = asmDb.prepare(`
    INSERT INTO asset
      (ip, is_exposed, asn, org, cdn, country_code, os_name, risk_score, first_seen, last_seen)
    VALUES
      (@ip, @is_exposed, @asn, @org, @cdn, @country_code, @os_name, @risk_score,
       TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'), TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
    ON CONFLICT DO NOTHING
  `)

  const assets = [
    { ip: '211.234.10.1',   is_exposed:1, asn:'AS9316',  org:'Hanwha Life Insurance',   cdn:null,          country_code:'KR', os_name:'Linux 5.x',   risk_score:72 },
    { ip: '211.234.10.2',   is_exposed:1, asn:'AS9316',  org:'Hanwha Life Insurance',   cdn:null,          country_code:'KR', os_name:'Linux 5.x',   risk_score:45 },
    { ip: '211.234.10.10',  is_exposed:1, asn:'AS9316',  org:'Hanwha Life Insurance',   cdn:null,          country_code:'KR', os_name:'Windows 2019',risk_score:88 },
    { ip: '203.0.113.50',   is_exposed:1, asn:'AS13335', org:'Cloudflare Inc.',          cdn:'Cloudflare',  country_code:'KR', os_name:null,          risk_score:12 },
    { ip: '203.0.113.51',   is_exposed:1, asn:'AS13335', org:'Cloudflare Inc.',          cdn:'Cloudflare',  country_code:'KR', os_name:null,          risk_score:8  },
    { ip: '10.10.1.5',      is_exposed:0, asn:null,      org:'Hanwha Internal',          cdn:null,          country_code:'KR', os_name:'Linux 4.x',   risk_score:35 },
    { ip: '10.10.1.20',     is_exposed:0, asn:null,      org:'Hanwha Internal',          cdn:null,          country_code:'KR', os_name:'Linux 5.x',   risk_score:25 },
  ]
  const insertAllAssets = asmDb.transaction(rows => rows.forEach(r => insertAsset.run(r)))
  insertAllAssets(assets)

  // ② FQDN 매핑 시드
  const insertName = asmDb.prepare(`
    INSERT INTO asset_name (asset_id, fqdn, root_domain, record_type, source)
    SELECT id, @fqdn, @root_domain, @record_type, @source
    FROM asset WHERE ip = @ip
    ON CONFLICT DO NOTHING
  `)

  const names = [
    { ip:'211.234.10.1',  fqdn:'hanwhalife.com',           root_domain:'hanwhalife.com',    record_type:'A',     source:'amass'     },
    { ip:'211.234.10.1',  fqdn:'www.hanwhalife.com',        root_domain:'hanwhalife.com',    record_type:'A',     source:'subfinder' },
    { ip:'211.234.10.1',  fqdn:'mobile.hanwhalife.com',     root_domain:'hanwhalife.com',    record_type:'A',     source:'subfinder' },
    { ip:'211.234.10.1',  fqdn:'m.hanwhalife.com',          root_domain:'hanwhalife.com',    record_type:'CNAME', source:'dnsx'      },
    { ip:'211.234.10.2',  fqdn:'direct.hanwhalife.com',     root_domain:'hanwhalife.com',    record_type:'A',     source:'amass'     },
    { ip:'211.234.10.2',  fqdn:'api.hanwhalife.com',        root_domain:'hanwhalife.com',    record_type:'A',     source:'dnsx'      },
    { ip:'211.234.10.10', fqdn:'admin.hanwhalife.com',      root_domain:'hanwhalife.com',    record_type:'A',     source:'amass'     },
    { ip:'211.234.10.10', fqdn:'dev.hanwhalife.com',        root_domain:'hanwhalife.com',    record_type:'A',     source:'amass'     },
    { ip:'203.0.113.50',  fqdn:'company.hanwhalife.com',    root_domain:'hanwhalife.com',    record_type:'A',     source:'subfinder' },
    { ip:'203.0.113.50',  fqdn:'recruit.hanwhalife.com',    root_domain:'hanwhalife.com',    record_type:'A',     source:'subfinder' },
    { ip:'203.0.113.51',  fqdn:'cdn.hanwhalife.com',        root_domain:'hanwhalife.com',    record_type:'CNAME', source:'dnsx'      },
    { ip:'203.0.113.51',  fqdn:'static.hanwhalife.com',     root_domain:'hanwhalife.com',    record_type:'CNAME', source:'dnsx'      },
    { ip:'10.10.1.5',     fqdn:'intranet.hanwhalife.internal', root_domain:'hanwhalife.internal', record_type:'A', source:'manual'  },
    { ip:'10.10.1.20',    fqdn:'db01.hanwhalife.internal',  root_domain:'hanwhalife.internal',   record_type:'A', source:'manual'  },
  ]
  const insertAllNames = asmDb.transaction(rows => rows.forEach(r => insertName.run(r)))
  insertAllNames(names)

  // ③ 네트워크 서비스 시드
  const insertSvc = asmDb.prepare(`
    INSERT INTO network_service
      (asset_id, ip, port, protocol, state, service_name, product, version, fingerprint_source)
    SELECT a.id, @ip, @port, @protocol, @state, @service_name, @product, @version, @src
    FROM asset a WHERE a.ip = @ip
    ON CONFLICT DO NOTHING
  `)

  const services = [
    { ip:'211.234.10.1',  port:80,   protocol:'tcp', state:'open', service_name:'http',  product:'nginx',       version:'1.24.0',  src:'nmap' },
    { ip:'211.234.10.1',  port:443,  protocol:'tcp', state:'open', service_name:'https', product:'nginx',       version:'1.24.0',  src:'nmap' },
    { ip:'211.234.10.1',  port:8080, protocol:'tcp', state:'open', service_name:'http',  product:'Tomcat',      version:'9.0.65',  src:'nmap' },
    { ip:'211.234.10.2',  port:80,   protocol:'tcp', state:'open', service_name:'http',  product:'nginx',       version:'1.22.1',  src:'nmap' },
    { ip:'211.234.10.2',  port:443,  protocol:'tcp', state:'open', service_name:'https', product:'nginx',       version:'1.22.1',  src:'nmap' },
    { ip:'211.234.10.2',  port:8443, protocol:'tcp', state:'open', service_name:'https', product:'Spring Boot', version:'2.7.0',   src:'nmap' },
    { ip:'211.234.10.10', port:80,   protocol:'tcp', state:'open', service_name:'http',  product:'IIS',         version:'10.0',    src:'nmap' },
    { ip:'211.234.10.10', port:443,  protocol:'tcp', state:'open', service_name:'https', product:'IIS',         version:'10.0',    src:'nmap' },
    { ip:'211.234.10.10', port:3389, protocol:'tcp', state:'open', service_name:'rdp',   product:'MS Terminal', version:null,      src:'nmap' },
    { ip:'211.234.10.10', port:445,  protocol:'tcp', state:'open', service_name:'smb',   product:'Samba',       version:'4.17.0',  src:'nmap' },
    { ip:'203.0.113.50',  port:80,   protocol:'tcp', state:'open', service_name:'http',  product:'cloudflare',  version:null,      src:'nmap' },
    { ip:'203.0.113.50',  port:443,  protocol:'tcp', state:'open', service_name:'https', product:'cloudflare',  version:null,      src:'nmap' },
    { ip:'10.10.1.5',     port:22,   protocol:'tcp', state:'open', service_name:'ssh',   product:'OpenSSH',     version:'8.9p1',   src:'nmap' },
    { ip:'10.10.1.5',     port:8080, protocol:'tcp', state:'open', service_name:'http',  product:'Tomcat',      version:'8.5.50',  src:'nmap' },
    { ip:'10.10.1.20',    port:3306, protocol:'tcp', state:'open', service_name:'mysql', product:'MySQL',       version:'8.0.32',  src:'nmap' },
    { ip:'10.10.1.20',    port:22,   protocol:'tcp', state:'open', service_name:'ssh',   product:'OpenSSH',     version:'7.4p1',   src:'nmap' },
  ]
  const insertAllSvcs = asmDb.transaction(rows => rows.forEach(r => insertSvc.run(r)))
  insertAllSvcs(services)

  // ④ HTTP 엔드포인트 시드
  const insertHttp = asmDb.prepare(`
    INSERT INTO http_endpoint
      (asset_id, url, fqdn, ip, port, scheme, status_code, title, web_server, technology,
       tls_version, response_time_ms)
    SELECT a.id, @url, @fqdn, @ip, @port, @scheme, @status_code, @title, @web_server,
           @technology, @tls_version, @response_time_ms
    FROM asset a WHERE a.ip = @ip
    ON CONFLICT DO NOTHING
  `)

  const endpoints = [
    { ip:'211.234.10.1',  url:'https://hanwhalife.com',         fqdn:'hanwhalife.com',         port:443, scheme:'https', status_code:200, title:'한화생명보험',           web_server:'nginx/1.24.0', technology:'["nginx","jQuery 3.6","Bootstrap 5"]', tls_version:'TLS 1.3', response_time_ms:320  },
    { ip:'211.234.10.1',  url:'https://www.hanwhalife.com',      fqdn:'www.hanwhalife.com',      port:443, scheme:'https', status_code:200, title:'한화생명보험',           web_server:'nginx/1.24.0', technology:'["nginx","jQuery 3.6","Bootstrap 5"]', tls_version:'TLS 1.3', response_time_ms:310  },
    { ip:'211.234.10.1',  url:'http://211.234.10.1:8080',        fqdn:null,                      port:8080,scheme:'http',  status_code:200, title:'Apache Tomcat/9.0.65',  web_server:'Apache-Coyote', technology:'["Tomcat","Java"]',                    tls_version:null,      response_time_ms:180  },
    { ip:'211.234.10.2',  url:'https://direct.hanwhalife.com',   fqdn:'direct.hanwhalife.com',   port:443, scheme:'https', status_code:200, title:'한화생명 다이렉트',      web_server:'nginx/1.22.1', technology:'["nginx","Vue.js 3","Webpack"]',        tls_version:'TLS 1.3', response_time_ms:280  },
    { ip:'211.234.10.2',  url:'https://api.hanwhalife.com',      fqdn:'api.hanwhalife.com',      port:443, scheme:'https', status_code:200, title:'API Gateway',           web_server:'nginx/1.22.1', technology:'["nginx","Spring Boot"]',               tls_version:'TLS 1.3', response_time_ms:95   },
    { ip:'211.234.10.10', url:'https://admin.hanwhalife.com',    fqdn:'admin.hanwhalife.com',    port:443, scheme:'https', status_code:200, title:'관리자 페이지',          web_server:'Microsoft-IIS/10.0', technology:'["IIS","ASP.NET","jQuery 1.8"]', tls_version:'TLS 1.2', response_time_ms:520  },
    { ip:'211.234.10.10', url:'https://dev.hanwhalife.com',      fqdn:'dev.hanwhalife.com',      port:443, scheme:'https', status_code:200, title:'개발 서버',              web_server:'Microsoft-IIS/10.0', technology:'["IIS","ASP.NET 4.7"]',         tls_version:'TLS 1.2', response_time_ms:440  },
    { ip:'203.0.113.50',  url:'https://company.hanwhalife.com',  fqdn:'company.hanwhalife.com',  port:443, scheme:'https', status_code:200, title:'한화생명 기업소개',      web_server:'cloudflare',   technology:'["Cloudflare","WordPress 6.3","PHP"]',  tls_version:'TLS 1.3', response_time_ms:210  },
  ]
  const insertAllHttp = asmDb.transaction(rows => rows.forEach(r => insertHttp.run(r)))
  insertAllHttp(endpoints)

  // ⑤ 취약점 시드
  const insertVuln = asmDb.prepare(`
    INSERT INTO vulnerability_finding
      (asset_id, ip, fqdn, url, port, service_name, template_id, template_name,
       severity, cvss_score, cve_id, tags, matched_at, status, first_seen, last_seen)
    SELECT a.id, @ip, @fqdn, @url, @port, @service_name,
           @template_id, @template_name, @severity, @cvss_score, @cve_id, @tags,
           @matched_at, @status, TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'), TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')
    FROM asset a WHERE a.ip = @ip
    ON CONFLICT DO NOTHING
  `)

  const vulns = [
    { ip:'211.234.10.10', fqdn:'admin.hanwhalife.com',  url:'https://admin.hanwhalife.com',    port:443,  service_name:'https', template_id:'CVE-2021-44228',  template_name:'Apache Log4Shell RCE',        severity:'critical', cvss_score:10.0, cve_id:'CVE-2021-44228', tags:'rce,log4j',         matched_at:'https://admin.hanwhalife.com', status:'open'  },
    { ip:'211.234.10.10', fqdn:'dev.hanwhalife.com',    url:'https://dev.hanwhalife.com',      port:443,  service_name:'https', template_id:'CVE-2023-44487',  template_name:'HTTP/2 Rapid Reset DoS',      severity:'high',     cvss_score:7.5,  cve_id:'CVE-2023-44487', tags:'dos,http2',         matched_at:'https://dev.hanwhalife.com',   status:'open'  },
    { ip:'211.234.10.10', fqdn:null,                   url:null,                              port:3389, service_name:'rdp',   template_id:'rdp-exposed-check', template_name:'RDP Exposed to Internet',    severity:'high',     cvss_score:8.1,  cve_id:null,             tags:'rdp,exposure',      matched_at:'211.234.10.10:3389',           status:'open'  },
    { ip:'211.234.10.10', fqdn:null,                   url:null,                              port:445,  service_name:'smb',   template_id:'smb-signing-check', template_name:'SMB Signing Disabled',       severity:'medium',   cvss_score:5.9,  cve_id:null,             tags:'smb,misconfiguration', matched_at:'211.234.10.10:445',           status:'open'  },
    { ip:'211.234.10.1',  fqdn:'hanwhalife.com',        url:'http://211.234.10.1:8080',        port:8080, service_name:'http',  template_id:'CVE-2020-1938',    template_name:'Tomcat AJP File Inclusion',   severity:'critical', cvss_score:9.8,  cve_id:'CVE-2020-1938',  tags:'rce,tomcat',        matched_at:'http://211.234.10.1:8080',     status:'open'  },
    { ip:'211.234.10.1',  fqdn:'hanwhalife.com',        url:'https://hanwhalife.com',          port:443,  service_name:'https', template_id:'ssl-tls-1-0',     template_name:'TLS 1.0 Supported',          severity:'medium',   cvss_score:5.3,  cve_id:null,             tags:'ssl,tls,outdated',  matched_at:'https://hanwhalife.com',       status:'acknowledged' },
    { ip:'211.234.10.2',  fqdn:'api.hanwhalife.com',    url:'https://api.hanwhalife.com',      port:443,  service_name:'https', template_id:'CVE-2022-22965',  template_name:'Spring4Shell RCE',            severity:'critical', cvss_score:9.8,  cve_id:'CVE-2022-22965', tags:'rce,spring',        matched_at:'https://api.hanwhalife.com',   status:'open'  },
    { ip:'211.234.10.2',  fqdn:'direct.hanwhalife.com', url:'https://direct.hanwhalife.com',   port:443,  service_name:'https', template_id:'xss-generic',     template_name:'Reflected XSS',              severity:'medium',   cvss_score:6.1,  cve_id:null,             tags:'xss,injection',     matched_at:'https://direct.hanwhalife.com',status:'open'  },
    { ip:'10.10.1.20',    fqdn:null,                   url:null,                              port:3306, service_name:'mysql', template_id:'mysql-unauth',     template_name:'MySQL Unauthorized Access',   severity:'high',     cvss_score:8.8,  cve_id:null,             tags:'mysql,unauth',      matched_at:'10.10.1.20:3306',              status:'open'  },
    { ip:'10.10.1.5',     fqdn:null,                   url:null,                              port:8080, service_name:'http',  template_id:'CVE-2019-0232',    template_name:'Tomcat CGI RCE',              severity:'high',     cvss_score:8.1,  cve_id:'CVE-2019-0232',  tags:'rce,tomcat,cgi',    matched_at:'http://10.10.1.5:8080',        status:'open'  },
    { ip:'203.0.113.50',  fqdn:'company.hanwhalife.com',url:'https://company.hanwhalife.com',  port:443,  service_name:'https', template_id:'wordpress-enum',  template_name:'WordPress User Enumeration',  severity:'low',      cvss_score:3.7,  cve_id:null,             tags:'wordpress,enum',    matched_at:'https://company.hanwhalife.com',status:'open' },
    { ip:'211.234.10.10', fqdn:'admin.hanwhalife.com',  url:'https://admin.hanwhalife.com',    port:443,  service_name:'https', template_id:'http-missing-hsts','template_name':'Missing HSTS Header',      severity:'low',      cvss_score:3.1,  cve_id:null,             tags:'header,misconfiguration', matched_at:'https://admin.hanwhalife.com', status:'open' },
  ]
  const insertAllVulns = asmDb.transaction(rows => rows.forEach(r => insertVuln.run(r)))
  insertAllVulns(vulns)

  // ⑥ asset_current 집계 갱신
  refreshAssetCurrent()

  // ⑦ 변경이력 시드
  const insertChange = asmDb.prepare(`
    INSERT INTO asset_change_log (change_type, asset_ip, detail, severity, detected_at)
    VALUES (@type, @ip, @detail, @sev, TO_CHAR(CURRENT_TIMESTAMP + (@offset::text || '')::interval,'YYYY-MM-DD HH24:MI:SS'))
  `)
  const changes = [
    { type:'new_asset',      ip:'211.234.10.10', detail:'{"msg":"새 자산 발견","ip":"211.234.10.10","fqdn":"admin.hanwhalife.com"}',     sev:'high',   offset:'-3 days' },
    { type:'new_port',       ip:'211.234.10.10', detail:'{"msg":"신규 포트 오픈","port":3389,"service":"rdp"}',                          sev:'high',   offset:'-2 days' },
    { type:'new_vuln',       ip:'211.234.10.10', detail:'{"msg":"신규 취약점","template":"CVE-2021-44228","severity":"critical"}',        sev:'critical',offset:'-1 days'},
    { type:'new_fqdn',       ip:'211.234.10.2',  detail:'{"msg":"신규 서브도메인","fqdn":"api.hanwhalife.com"}',                          sev:'medium', offset:'-5 days' },
    { type:'version_change', ip:'211.234.10.1',  detail:'{"msg":"서비스 버전 변경","port":8080,"old":"Tomcat/8.5","new":"Tomcat/9.0.65"}',sev:'medium', offset:'-6 days' },
    { type:'new_asset',      ip:'10.10.1.20',    detail:'{"msg":"새 자산 발견","ip":"10.10.1.20","fqdn":"db01.hanwhalife.internal"}',     sev:'medium', offset:'-7 days' },
    { type:'new_vuln',       ip:'10.10.1.20',    detail:'{"msg":"MySQL 미인증 접근 취약점 발견","template":"mysql-unauth"}',               sev:'high',   offset:'-4 days' },
  ]
  const insertAllChanges = asmDb.transaction(rows => rows.forEach(r => insertChange.run({ type:r.type, ip:r.ip, detail:r.detail, sev:r.sev, offset:r.offset })))
  insertAllChanges(changes)

  console.log('[ASM-DB] 시드 데이터 주입 완료')
})()

// ════════════════════════════════════════════════════════════════
//  asset_current 집계 함수 (파싱 결과 후 호출)
// ════════════════════════════════════════════════════════════════
function refreshAssetCurrent() {
  const assets = asmDb.prepare('SELECT * FROM asset').all()

  const upsert = asmDb.prepare(`
    INSERT INTO asset_current
      (ip, asset_id, fqdns, root_domains, is_exposed, is_internal, asn, cdn, os_name,
       open_ports, service_summary, web_titles, technologies,
       risk_score, vuln_critical, vuln_high, vuln_medium, vuln_low, vuln_info,
       first_seen, last_seen, status)
    VALUES
      (@ip, @asset_id, @fqdns, @root_domains, @is_exposed, @is_internal, @asn, @cdn, @os_name,
       @open_ports, @service_summary, @web_titles, @technologies,
       @risk_score, @vuln_critical, @vuln_high, @vuln_medium, @vuln_low, @vuln_info,
       @first_seen, @last_seen, @status)
    ON CONFLICT(ip) DO UPDATE SET
      fqdns=@fqdns, root_domains=@root_domains, is_exposed=@is_exposed,
      asn=@asn, cdn=@cdn, os_name=@os_name,
      open_ports=@open_ports, service_summary=@service_summary,
      web_titles=@web_titles, technologies=@technologies,
      risk_score=@risk_score,
      vuln_critical=@vuln_critical, vuln_high=@vuln_high,
      vuln_medium=@vuln_medium, vuln_low=@vuln_low, vuln_info=@vuln_info,
      last_seen=@last_seen, status=@status
  `)

  const tx = asmDb.transaction(() => {
    for (const a of assets) {
      // FQDN 목록
      const names = asmDb.prepare('SELECT fqdn, root_domain FROM asset_name WHERE asset_id=?').all(a.id)
      const fqdns = names.map(n => n.fqdn)
      const rootDomains = [...new Set(names.map(n => n.root_domain).filter(Boolean))]

      // 오픈 포트
      const svcs = asmDb.prepare("SELECT * FROM network_service WHERE asset_id=? AND state='open'").all(a.id)
      const openPorts = svcs.map(s => s.port)
      const svcSummary = {}
      svcs.forEach(s => { svcSummary[s.port] = `${s.service_name||''}${s.product ? '/'+s.product : ''}${s.version ? ' '+s.version : ''}`.trim() })

      // 웹 타이틀 & 기술스택
      const httpsRows = asmDb.prepare('SELECT title, technology FROM http_endpoint WHERE asset_id=?').all(a.id)
      const webTitles = [...new Set(httpsRows.map(h => h.title).filter(Boolean))]
      const techSet = new Set()
      httpsRows.forEach(h => {
        if (h.technology) {
          try { JSON.parse(h.technology).forEach(t => techSet.add(t)) } catch {}
        }
      })

      // 취약점 집계
      const vulnCounts = asmDb.prepare(`
        SELECT severity, COUNT(*) AS cnt
        FROM vulnerability_finding
        WHERE asset_id=? AND status NOT IN ('fixed','false_positive')
        GROUP BY severity
      `).all(a.id)
      const vc = { critical:0, high:0, medium:0, low:0, info:0 }
      vulnCounts.forEach(r => { if (vc[r.severity] !== undefined) vc[r.severity] = r.cnt })

      upsert.run({
        ip: a.ip, asset_id: a.id,
        fqdns: JSON.stringify(fqdns),
        root_domains: JSON.stringify(rootDomains),
        is_exposed: a.is_exposed, is_internal: a.is_internal,
        asn: a.asn, cdn: a.cdn, os_name: a.os_name,
        open_ports: JSON.stringify(openPorts),
        service_summary: JSON.stringify(svcSummary),
        web_titles: JSON.stringify(webTitles),
        technologies: JSON.stringify([...techSet]),
        risk_score: a.risk_score,
        vuln_critical: vc.critical, vuln_high: vc.high,
        vuln_medium: vc.medium, vuln_low: vc.low, vuln_info: vc.info,
        first_seen: a.first_seen, last_seen: a.last_seen,
        status: a.status
      })
    }
  })
  tx()
}

module.exports = { asmDb, refreshAssetCurrent }
