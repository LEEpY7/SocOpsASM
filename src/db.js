'use strict'

const Database = require('./pg-compat')

const db = new Database()

// WAL 모드 – 동시 읽기/쓰기 성능 향상
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

// =================================================================
//  ██████  SCHEMA v2 — 모듈별 테이블 네임스페이스 분리
//
//  모듈 A : 가용성 모니터링  (avail_*)
//  모듈 B : 블랙박스 공격 대시보드 (attack_*)
//  공통   : alert_configs / alert_history / alert_state
//
//  ※ 기존 targets / probe_results 는 avail_targets / avail_probe_results 로
//    마이그레이션 후 VIEW 로 하위 호환성 유지
// =================================================================

db.exec(`
  -- ────────────────────────────────────────────────────────────
  --  모듈 A : 가용성 모니터링
  -- ────────────────────────────────────────────────────────────

  CREATE TABLE IF NOT EXISTS avail_targets (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    url          TEXT NOT NULL UNIQUE,
    category     TEXT NOT NULL DEFAULT 'other',
    sub_category TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    interval_sec INTEGER NOT NULL DEFAULT 60,
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    updated_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  CREATE TABLE IF NOT EXISTS avail_probe_results (
    id               BIGSERIAL PRIMARY KEY,
    target_id        INTEGER NOT NULL,
    probe_time       TEXT    DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),

    -- 기본 가용성
    probe_success    INTEGER,   -- 1=UP / 0=DOWN
    probe_failed     INTEGER,   -- 1=실패(네트워크 오류 등)

    -- HTTP 상세
    http_status_code INTEGER,
    http_version     TEXT,
    http_redirects   INTEGER,
    http_content_length INTEGER,
    http_duration_resolve_ms    REAL,
    http_duration_connect_ms    REAL,
    http_duration_tls_ms        REAL,
    http_duration_processing_ms REAL,
    http_duration_transfer_ms   REAL,

    -- 전체 응답시간
    probe_duration_ms REAL,

    -- TLS/SSL
    tls_version         TEXT,
    tls_cipher          TEXT,
    ssl_expiry_days     INTEGER,
    ssl_earliest_expiry TEXT,

    -- DNS
    dns_lookup_ms REAL,

    -- 오류 메시지
    error_msg TEXT,

    FOREIGN KEY (target_id) REFERENCES avail_targets(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_avail_probe_target_time
    ON avail_probe_results(target_id, probe_time DESC);

  -- ────────────────────────────────────────────────────────────
  --  모듈 B : 블랙박스 공격 대시보드
  --  (향후 세부 데이터 수집 모듈 연동 예정 — 현재는 기본 틀만)
  -- ────────────────────────────────────────────────────────────

  -- 공격 대상 자산 등록
  CREATE TABLE IF NOT EXISTS attack_assets (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    asset_type   TEXT NOT NULL DEFAULT 'web',  -- web | api | infra | mobile
    host         TEXT NOT NULL,
    port         INTEGER DEFAULT 443,
    description  TEXT,
    group_name   TEXT,                         -- 자산 그룹 (예: DMZ, 내부망)
    owner        TEXT,                         -- 담당자/부서
    enabled      INTEGER NOT NULL DEFAULT 1,
    tags         TEXT,                         -- JSON 배열 문자열
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    updated_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  -- 공격/위협 이벤트 로그
  CREATE TABLE IF NOT EXISTS attack_events (
    id           BIGSERIAL PRIMARY KEY,
    asset_id     INTEGER,
    event_time   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    event_type   TEXT NOT NULL,   -- scan | exploit | ddos | brute_force | anomaly | other
    severity     TEXT NOT NULL DEFAULT 'info', -- critical | high | medium | low | info
    source_ip    TEXT,
    source_country TEXT,
    dest_port    INTEGER,
    protocol     TEXT,
    payload_info TEXT,
    status       TEXT DEFAULT 'open',  -- open | acknowledged | resolved | false_positive
    description  TEXT,
    raw_data     TEXT,                 -- JSON 원시 데이터
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    FOREIGN KEY (asset_id) REFERENCES attack_assets(id) ON DELETE SET NULL
  );

  CREATE INDEX IF NOT EXISTS idx_attack_events_time
    ON attack_events(event_time DESC);
  CREATE INDEX IF NOT EXISTS idx_attack_events_severity
    ON attack_events(severity, event_time DESC);
  CREATE INDEX IF NOT EXISTS idx_attack_events_asset
    ON attack_events(asset_id, event_time DESC);

  -- 공격 통계 요약 (일별 집계 캐시)
  CREATE TABLE IF NOT EXISTS attack_stats_daily (
    id           BIGSERIAL PRIMARY KEY,
    stat_date    TEXT NOT NULL,              -- YYYY-MM-DD
    asset_id     INTEGER,
    event_type   TEXT,
    severity     TEXT,
    event_count  INTEGER DEFAULT 0,
    unique_sources INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    UNIQUE(stat_date, asset_id, event_type, severity)
  );

  -- ────────────────────────────────────────────────────────────
  --  공통 : 경보 관리
  -- ────────────────────────────────────────────────────────────

  CREATE TABLE IF NOT EXISTS alert_configs (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    module        TEXT NOT NULL DEFAULT 'availability', -- availability | attack | system
    to_email      TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    -- 가용성 모니터링 알림 조건
    down_notify   INTEGER NOT NULL DEFAULT 1,
    threshold_ms  INTEGER NOT NULL DEFAULT 3000,
    ssl_warn_days INTEGER NOT NULL DEFAULT 30,
    -- 공격 대시보드 알림 조건 (향후 활성화)
    severity_filter TEXT DEFAULT 'critical,high', -- 알림 발생 심각도 필터
    created_at    TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS'))
  );

  CREATE TABLE IF NOT EXISTS alert_history (
    id              BIGSERIAL PRIMARY KEY,
    module          TEXT NOT NULL DEFAULT 'availability', -- 어느 모듈에서 발생했는지
    target_id       INTEGER,          -- avail_targets.id 또는 attack_assets.id
    alert_config_id INTEGER,
    alert_type      TEXT,             -- down | slow | ssl_expiry | attack_critical | attack_high
    message         TEXT,
    sent_at         TEXT DEFAULT (TO_CHAR(CURRENT_TIMESTAMP,'YYYY-MM-DD HH24:MI:SS')),
    success         INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS alert_state (
    module       TEXT NOT NULL DEFAULT 'availability',
    target_id    INTEGER NOT NULL,
    is_alerting  INTEGER DEFAULT 0,
    alerted_at   TEXT,
    PRIMARY KEY (module, target_id)
  );

  -- ────────────────────────────────────────────────────────────
  --  하위 호환 VIEW — 기존 코드가 targets / probe_results 를
  --  참조해도 동작하도록 (마이그레이션 과도기)
  -- ────────────────────────────────────────────────────────────

  CREATE OR REPLACE VIEW targets AS
    SELECT * FROM avail_targets;

  CREATE OR REPLACE VIEW probe_results AS
    SELECT * FROM avail_probe_results;
`)

// ─── 마이그레이션: 기존 targets → avail_targets ─────────────────
//  targets 테이블(구버전)이 실제 테이블로 존재하면 데이터를 이전 후 삭제
// PostgreSQL 전환으로 sqlite_master 기반 레거시 마이그레이션은 생략


// ─── 시드: 가용성 모니터링 초기 타겟 ────────────────────────────
;(function seedAvailTargets() {
  const cnt = db.prepare('SELECT COUNT(*) as c FROM avail_targets').get()
  if (cnt.c > 0) return

  const insert = db.prepare(`
    INSERT INTO avail_targets (name, url, category, sub_category)
    VALUES (@name, @url, @category, @sub_category)
    ON CONFLICT DO NOTHING
  `)
  const seeds = [
    // 한화생명
    { name: '대표홈페이지',  url: 'https://hanwhalife.com',        category: 'hanwha',      sub_category: '대표사이트' },
    { name: '다이렉트',       url: 'https://direct.hanwhalife.com', category: 'hanwha',      sub_category: '다이렉트'  },
    // 금융기관
    { name: '한국은행',       url: 'https://www.bok.or.kr',         category: 'institution', sub_category: '중앙은행'  },
    { name: '금융감독원',     url: 'https://www.fss.or.kr',         category: 'institution', sub_category: '감독기관'  },
    { name: '금융위원회',     url: 'https://www.fsc.go.kr/index',   category: 'institution', sub_category: '감독기관'  },
    { name: '금융결제원',     url: 'https://www.kftc.or.kr',        category: 'institution', sub_category: '결제인프라'},
    { name: '예금보험공사',   url: 'https://www.kdic.or.kr',        category: 'institution', sub_category: '보험기관'  },
    { name: '한국거래소',     url: 'https://www.krx.co.kr',         category: 'institution', sub_category: '증권거래소'},
    { name: '신용보증기금',   url: 'https://www.kodit.co.kr',       category: 'institution', sub_category: '보증기관'  },
    { name: '기술보증기금',   url: 'https://www.kibo.or.kr',        category: 'institution', sub_category: '보증기관'  },
    // 은행
    { name: 'KB국민은행',     url: 'https://www.kbstar.com',        category: 'bank',        sub_category: '시중은행'  },
    { name: '신한은행',       url: 'https://www.shinhan.com',       category: 'bank',        sub_category: '시중은행'  },
    { name: '우리은행',       url: 'https://www.wooribank.com',     category: 'bank',        sub_category: '시중은행'  },
    { name: '하나은행',       url: 'https://www.kebhana.com',       category: 'bank',        sub_category: '시중은행'  },
    { name: 'NH농협은행',     url: 'https://banking.nonghyup.com',  category: 'bank',        sub_category: '특수은행'  },
    { name: 'IBK기업은행',    url: 'https://www.ibk.co.kr',         category: 'bank',        sub_category: '특수은행'  },
    { name: '산업은행',       url: 'https://www.kdb.co.kr',         category: 'bank',        sub_category: '특수은행'  },
    { name: '카카오뱅크',     url: 'https://www.kakaobank.com',     category: 'bank',        sub_category: '인터넷은행'},
    { name: '케이뱅크',       url: 'https://www.kbanknow.com',      category: 'bank',        sub_category: '인터넷은행'},
    { name: '토스뱅크',       url: 'https://www.tossbank.com',      category: 'bank',        sub_category: '인터넷은행'},
    // 카드
    { name: '신한카드',       url: 'https://www.shinhancard.com',   category: 'card',        sub_category: '카드사'    },
    { name: '삼성카드',       url: 'https://www.samsungcard.com',   category: 'card',        sub_category: '카드사'    },
    { name: '현대카드',       url: 'https://www.hyundaicard.com',   category: 'card',        sub_category: '카드사'    },
    { name: 'KB국민카드',     url: 'https://card.kbcard.com',       category: 'card',        sub_category: '카드사'    },
    { name: '롯데카드',       url: 'https://www.lottecard.co.kr',   category: 'card',        sub_category: '카드사'    },
    { name: '우리카드',       url: 'https://pc.wooricard.com',      category: 'card',        sub_category: '카드사'    },
    { name: '하나카드',       url: 'https://www.hanacard.co.kr',    category: 'card',        sub_category: '카드사'    },
    { name: 'BC카드',         url: 'https://www.bccard.com',        category: 'card',        sub_category: '카드사'    },
    // 보험
    { name: '삼성생명',       url: 'https://www.samsunglife.com',   category: 'insurance',   sub_category: '생명보험'  },
    { name: '교보생명',       url: 'https://www.kyobo.com',         category: 'insurance',   sub_category: '생명보험'  },
    { name: 'NH농협생명',     url: 'https://www.nhlife.co.kr',      category: 'insurance',   sub_category: '생명보험'  },
    { name: '삼성화재',       url: 'https://www.samsungfire.com',   category: 'insurance',   sub_category: '손해보험'  },
    { name: 'DB손해보험',     url: 'https://www.idbins.com',        category: 'insurance',   sub_category: '손해보험'  },
    { name: '현대해상',       url: 'https://www.hi.co.kr',          category: 'insurance',   sub_category: '손해보험'  },
    { name: 'KB손해보험',     url: 'https://www.kbinsure.co.kr',    category: 'insurance',   sub_category: '손해보험'  },
    { name: '메리츠화재',     url: 'https://www.meritzfire.com',    category: 'insurance',   sub_category: '손해보험'  },
    { name: '롯데손해보험',   url: 'https://www.lotteins.co.kr',    category: 'insurance',   sub_category: '손해보험'  },
    // 증권
    { name: 'NH투자증권',     url: 'https://www.nhqv.com',          category: 'securities',  sub_category: '종합증권'  },
    { name: '미래에셋증권',   url: 'https://securities.miraeasset.com', category: 'securities', sub_category: '종합증권'},
    { name: '삼성증권',       url: 'https://www.samsungsecurities.com', category: 'securities', sub_category: '종합증권'},
    { name: 'KB증권',         url: 'https://www.kbsec.com',         category: 'securities',  sub_category: '종합증권'  },
    { name: '키움증권',       url: 'https://www.kiwoom.com',        category: 'securities',  sub_category: '온라인증권'},
    { name: '한국투자증권',   url: 'https://www.truefriend.com',    category: 'securities',  sub_category: '종합증권'  },
    { name: '신한투자증권',   url: 'https://www.shinhansec.com',    category: 'securities',  sub_category: '종합증권'  },
    { name: '카카오페이증권', url: 'https://kakaopaysec.com/',      category: 'securities',  sub_category: '온라인증권'}
  ]
  const insertAll = db.transaction(rows => rows.forEach(r => insert.run(r)))
  insertAll(seeds)
  console.log(`[DB] 가용성 모니터링 시드 ${seeds.length}건 삽입 완료`)
})()

// ─── 시드: 공격 대시보드 샘플 자산 ──────────────────────────────
;(function seedAttackAssets() {
  const cnt = db.prepare('SELECT COUNT(*) as c FROM attack_assets').get()
  if (cnt.c > 0) return

  const insert = db.prepare(`
    INSERT INTO attack_assets (name, asset_type, host, port, description, group_name, owner)
    VALUES (@name, @asset_type, @host, @port, @description, @group_name, @owner)
    ON CONFLICT DO NOTHING
  `)
  const seeds = [
    { name: '대표 웹사이트',    asset_type: 'web',   host: 'hanwhalife.com',        port: 443,  description: '한화생명 공식 홈페이지',      group_name: 'DMZ',   owner: '인프라팀' },
    { name: '다이렉트 채널',    asset_type: 'web',   host: 'direct.hanwhalife.com', port: 443,  description: '다이렉트 보험 가입 채널',    group_name: 'DMZ',   owner: '인프라팀' },
    { name: '고객 API Gateway', asset_type: 'api',   host: 'api.hanwhalife.com',    port: 443,  description: '모바일·외부 API 진입점',     group_name: 'DMZ',   owner: '개발팀'   },
    { name: '내부 관리 서버',   asset_type: 'infra', host: '10.0.1.10',             port: 8443, description: '내부 관리 인터페이스',        group_name: '내부망', owner: '보안팀'   }
  ]
  const insertAll = db.transaction(rows => rows.forEach(r => insert.run(r)))
  insertAll(seeds)
  console.log(`[DB] 공격 대시보드 샘플 자산 ${seeds.length}건 삽입 완료`)
})()

module.exports = db
