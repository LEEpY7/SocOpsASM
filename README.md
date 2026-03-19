# SocOpsASM — 금융권 ASM 보안관제 플랫폼

> **한화생명 보안관제센터** — 가용성 모니터링 + 블랙박스 공격 대시보드(ASM) 통합 플랫폼

---

## 프로젝트 개요

SOC 담당자용 **외부 시점 웹 가용성 모니터링 + 공격표면 관리(ASM)** 통합 시스템.

- **가용성 모니터링**: 실제 Prometheus Blackbox Exporter를 통해 국내 전체 금융사 HTTP 프로브 수행
- **블랙박스 공격 대시보드(ASM)**: 오픈소스 보안 툴 파이프라인으로 외부 공격표면 자동 탐지·분석

---

## 아키텍처

```
[PM2]
  ├─ blackbox_exporter  (port 9115)
  │     GET /probe?target=<url>&module=http_2xx
  │     → Prometheus text format 메트릭 반환
  └─ finmonitor  (port 3000)
        ├─ 가용성 모니터링  → PostgreSQL (avail 스키마 성격, 7일 보관 정책)
        └─ ASM 파이프라인  → PostgreSQL (ASM 스키마)
              Amass → Subfinder → dnsx → Naabu → Masscan → Nmap → httpx → Nuclei
```

**기술 스택**

| 구분 | 기술 |
|------|------|
| 프로브 | Blackbox Exporter v0.25.0 |
| 백엔드 | Node.js 18 + Express |
| DB | PostgreSQL 14+ (`pg` 기반 래퍼) |
| 스케줄러 | node-cron |
| 알림 | nodemailer (Gmail SMTP) |
| 프론트엔드 | Vanilla JS SPA (다크 테마) |
| 차트 | Chart.js (로컬 번들) |
| 아이콘 | FontAwesome (로컬 번들) |
| 프로세스 관리 | PM2 |

---

## 메뉴 구성

### ① 가용성 모니터링

| 메뉴 | 설명 |
|------|------|
| 실시간 대시보드 | 전체 현황 카드, 장애 알람 배너, 카테고리 탭, 타겟 카드 (클릭 시 상세 모달) |
| 수집 이력 (7일) | 가용률 테이블, 응답시간 통계, 24h 차트 |
| 대상 관리 | CRUD, 활성/비활성 토글, 국내 금융사 일괄 등록 (50+ 기관) |

### ② 블랙박스 공격 대시보드 (ASM)

| 메뉴 | 설명 |
|------|------|
| **스캔 관리** | 스캔 대상(IP 대역/도메인) 등록·수정·삭제, 파이프라인 실행·취소, 단계별 진행 상태 실시간 모니터링 |
| **요약 대시보드** | 총 자산수·노출 IP/FQDN·오픈포트·웹서비스 카드, 심각도 분포 바, Top-10 오픈포트, 위험 자산 순위, 변경 이력 |
| **자산 인벤토리** | IP 우선 정렬, FQDN 그룹핑, 14개 컬럼 테이블, 필터·정렬·페이지네이션, 자산 상세 슬라이드 드로어 |
| **취약점 현황** | 13개 컬럼 테이블, 심각도·상태·CVE 필터, 인라인 상태 변경, CVE → NVD 링크 |

### ③ 경보 관리

| 메뉴 | 설명 |
|------|------|
| 알림 설정 | Gmail SMTP, DOWN/응답지연/SSL만료 알림 조건 설정 |
| 알림 이력 | 발송 내역 조회 |

---

## 블랙박스 공격 대시보드 — 파이프라인 상세

### 스캔 파이프라인 (8단계)

```
사용자가 IP대역/도메인 등록
        ↓
[스캔 시작] → 비동기 파이프라인 실행 (runId 즉시 반환)
        ↓
① Amass      — 패시브 서브도메인 열거 (Certificate/DNS/Scraping)
② Subfinder  — 서브도메인 열거 (보조, 다수 소스 활용)
③ dnsx       — DNS 확인 (FQDN → IP 매핑, A 레코드)
④ Naabu      — 빠른 포트 스캔 (Top 25 포트, rate 1000)
⑤ Masscan    — 대규모 포트 스캔 (IP 대역 전용, root 권한 필요)
⑥ Nmap       — 서비스·버전 탐지 (-sV -sC, OS 핑거프린팅)
⑦ httpx      — 웹 배너·기술스택 식별 (title, server, tech-detect)
⑧ Nuclei     — 취약점 스캔 (critical/high/medium, CVE/exposure/misconfiguration)
        ↓
결과 → Raw Zone (원본 보존) + Normalized Zone (정규화)
     → asset_current 뷰 갱신 → asset_change_log 변경 감지
```

### DB 레이어 구조

```
① Raw Zone      — 툴 출력 원문 보존
   raw_amass, raw_subfinder, raw_dnsx, raw_naabu,
   raw_masscan, raw_nmap, raw_httpx, raw_nuclei

② Normalized    — 정규화된 자산/서비스/취약점
   asset, asset_name, dns_record, network_service,
   http_endpoint, vulnerability_finding

③ Current State — 현재 상태 집계 뷰
   asset_current, service_current, http_current, vuln_current

④ Snapshot      — 일 단위 스냅샷
   asset_snapshot, vuln_snapshot

⑤ Change Log    — 변화 감지 기록
   asset_change_log

⑥ Pipeline      — 스캔 파이프라인 관리
   scan_target, pipeline_run, pipeline_stage_log
```

### 자산 인벤토리 컬럼 (14개)

| 컬럼 | 설명 |
|------|------|
| IP | 자산 IP 주소 (정렬 기준) |
| Domain/FQDN | 연결된 FQDN 목록 (칩 형태, +N 오버플로우) |
| Root Domain | 루트 도메인 |
| 노출 | 외부 노출 여부 플래그 |
| ASN/CDN | 네트워크 정보 |
| Open Ports | 오픈 포트 목록 |
| 주요 서비스 | 포트별 서비스명/버전 |
| OS | 운영체제 정보 |
| Web Title | HTTP 타이틀 |
| 기술스택 | 탐지된 기술 (칩) |
| 위험도 | Risk Score (0–100) |
| 취약점 | Critical/High/Medium/Low 카운트 뱃지 |
| First/Last Seen | 최초/최근 탐지 일시 |
| Status | active/inactive |

### 취약점 현황 컬럼 (13개)

| 컬럼 | 설명 |
|------|------|
| IP | 자산 IP |
| Domain | 연결 도메인 |
| URL/Target | 취약점 발견 URL |
| Port | 포트 |
| Service | 서비스명 |
| 취약점명 | Nuclei 템플릿 이름 |
| Template ID | Nuclei 템플릿 ID |
| CVE | CVE 번호 (NVD 링크) |
| Severity | critical/high/medium/low/info |
| CVSS | CVSS 점수 |
| Status | open/acknowledged/fixed/false_positive |
| First Seen | 최초 발견 |
| Last Seen | 최근 확인 |

---

## API 엔드포인트

### 가용성 모니터링

| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/health` | 서버 상태 |
| GET | `/api/status` | 전체 프로브 현황 |
| GET | `/api/targets` | 모니터링 대상 목록 |
| POST | `/api/targets` | 대상 추가 |
| PUT | `/api/targets/:id` | 대상 수정 |
| DELETE | `/api/targets/:id` | 대상 삭제 |
| GET | `/api/history/:id` | 프로브 이력 |

### 블랙박스 공격 대시보드 (ASM)

| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/asm/targets` | 스캔 대상 목록 |
| POST | `/api/asm/targets` | 스캔 대상 추가 (IP대역/도메인) |
| PUT | `/api/asm/targets/:id` | 스캔 대상 수정 |
| DELETE | `/api/asm/targets/:id` | 스캔 대상 삭제 |
| POST | `/api/asm/scan/start` | 전체 파이프라인 시작 |
| GET | `/api/asm/scan/status/:id` | 파이프라인 진행 상태 |
| GET | `/api/asm/scan/list` | 파이프라인 실행 이력 |
| POST | `/api/asm/scan/cancel/:id` | 파이프라인 취소 |
| GET | `/api/asm/summary` | 요약 대시보드 데이터 |
| GET | `/api/asm/inventory` | 자산 인벤토리 (페이지네이션·필터) |
| GET | `/api/asm/inventory/:ip` | 단일 자산 상세 |
| GET | `/api/asm/vulns` | 취약점 현황 (페이지네이션·필터) |
| PATCH | `/api/asm/vulns/:id/status` | 취약점 상태 변경 |
| GET | `/api/asm/changes` | 변경 이력 |

---

## 설치 및 실행

### PostgreSQL 전용 안내 (중요)

- 본 프로젝트는 **PostgreSQL만 지원**합니다.
- 애플리케이션 데이터는 로컬 `*.db` 파일이 아니라 PostgreSQL DB(`socopsasm` 예시)에 저장됩니다.
- 서버 시작 시 스키마/시드가 자동 반영됩니다.

### 요구사항
- Node.js 18+
- npm
- PostgreSQL 14+
- (ASM 파이프라인) amass, subfinder, dnsx, naabu, masscan, nmap, httpx(projectdiscovery), nuclei

### 먼저 이해하면 덜 헷갈리는 실행 구조

- **PostgreSQL**: 별도로 켜져 있어야 하는 DBMS입니다.
- **Blackbox Exporter**: 가용성 프로브를 수행하는 별도 프로세스입니다.
- **SocOpsASM 서버**: Node.js 앱이며 `npm start`로 직접 실행할 수 있습니다.
- **PM2**: 위 프로세스들을 백그라운드에서 관리하는 실행 관리자입니다.

즉, 실행 방식은 아래 둘 중 하나로 이해하시면 됩니다.

1. **수동 실행**
   - PostgreSQL 먼저 실행
   - Blackbox Exporter 실행
   - `npm start`로 앱 실행

2. **PM2 실행(권장)**
   - PostgreSQL 먼저 실행
   - `pm2 start ecosystem.config.cjs` 실행
   - PM2가 **앱 서버 + Blackbox Exporter**를 함께 관리

> 정리하면: **DBMS(PostgreSQL)는 PM2가 대신 켜주지 않습니다.**
> PostgreSQL은 먼저 살아 있어야 하고, 그 다음 앱은 `npm start` 또는 `pm2` 둘 중 하나로 실행합니다.

### 1) 첫 설치(최초 1회)

#### 1-1. 프로젝트 설치

```bash
git clone https://github.com/LEEpY7/SocOpsASM.git
cd SocOpsASM
npm install
```

> 현재 저장소 스냅샷에는 `package-lock.json`이 없을 수 있습니다. 로컬/배포 환경에서 `npm install`을 실행해 lockfile을 생성한 뒤 고정 배포하는 것을 권장합니다.

#### 1-2. 권장 디렉토리 레이아웃 (hanwha 기준)

```
/Users/leejiyu/Desktop/hanwha
├── apps/
│   └── SocOpsASM/
└── tools/
    ├── amass
    ├── subfinder
    ├── dnsx
    ├── naabu
    ├── masscan
    ├── nmap
    ├── httpx
    └── nuclei
```

> 툴을 `hanwha/tools`에 공용으로 두려면 `.env`에 `ASM_TOOLS_DIR=/Users/leejiyu/Desktop/hanwha/tools`를 설정하세요.
> 설정이 없으면 기본값 `<project>/tools`를 사용합니다.

#### 1-3. 환경변수 설정 (PostgreSQL + Gmail 알림 사용 시)

```bash
cp .env.example .env
# .env 파일 편집 — PostgreSQL 접속 정보 + Gmail 앱 비밀번호 설정
```

#### 1-4. PostgreSQL 초기 준비

```bash
# (예: macOS/Homebrew)
brew install postgresql@16
brew services start postgresql@16

# DB/계정 생성 예시
createuser -s postgres || true
createdb socopsasm || true

# 또는 psql로 직접 생성
# psql -U postgres -c "CREATE DATABASE socopsasm;"
```

> 앱 최초 기동 시 스키마/시드 데이터는 자동 생성됩니다.

#### 1-5. PostgreSQL 연결 확인

```bash
# 접속 테스트
psql "$DATABASE_URL" -c "SELECT now();"

# 기본 DB 미사용 시(개별 변수 사용)
psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT now();"
```

#### 1-6. 첫 실행

처음에는 아래 둘 중 **하나만 선택**해서 실행하면 됩니다.

##### 방법 A. 수동 실행 (`npm start`)

PostgreSQL은 먼저 켜 둔 상태여야 합니다.

```bash
# 1) PostgreSQL 실행 상태 확인/기동
brew services start postgresql@16   # 예시

# 2) Blackbox Exporter 실행
./blackbox/blackbox_exporter --config.file=./blackbox/blackbox.yml --web.listen-address=0.0.0.0:9115
```

다른 터미널에서:

```bash
# 3) Node 앱 실행
npm start
```

##### 방법 B. PM2 실행 (권장)

PostgreSQL은 먼저 켜 둔 상태여야 합니다.

```bash
# PostgreSQL은 별도로 실행된 상태여야 함
pm2 start ecosystem.config.cjs

# 상태 확인
pm2 list
pm2 logs --nostream
```

> `ecosystem.config.cjs`는 프로젝트 루트 기준 상대 경로를 사용하므로,
> 저장소를 `/Users/leejiyu/Desktop/hanwha/SocOpsASM`처럼 다른 위치로 옮겨도 그대로 동작합니다.
>
> PM2 방식에서는 `npm start`를 **같이 실행하지 않습니다.**
> `pm2 start ecosystem.config.cjs`가 앱 서버와 Blackbox Exporter를 대신 관리합니다.

### 2) 첫 설치 이후 실행 (평소 재실행 절차)

서버 재부팅 후나 다음 날 다시 켤 때는 아래 순서로 보면 됩니다.

#### 2-1. PostgreSQL 먼저 실행

```bash
brew services start postgresql@16   # 예시
```

#### 2-2. 앱 실행 방식 선택

##### 평소 운영용: PM2 사용

```bash
pm2 start ecosystem.config.cjs
pm2 list
pm2 logs --nostream
```

이미 PM2에 등록되어 있다면 다음처럼 재시작해도 됩니다.

```bash
pm2 restart finmonitor
pm2 restart blackbox
```

### 3) PostgreSQL에서 데이터 초기화하는 방법

소스코드에 더미데이터 필터를 두지 않았기 때문에, 초기화가 필요하면 **DB에서 직접 비우는 방식**을 권장합니다.

#### 3-1. ASM 데이터만 초기화

```bash
psql "$DATABASE_URL" <<'SQL'
BEGIN;
TRUNCATE TABLE
  pipeline_stage_log,
  pipeline_run,
  scan_job,
  raw_amass,
  raw_subfinder,
  raw_dnsx,
  raw_naabu,
  raw_masscan,
  raw_nmap,
  raw_httpx,
  raw_nuclei,
  vulnerability_finding,
  http_endpoint,
  network_service,
  dns_record,
  asset_name,
  asset_change_log,
  asset_snapshot,
  vuln_snapshot,
  service_current,
  http_current,
  vuln_current,
  asset_current,
  asset
RESTART IDENTITY;
COMMIT;
SQL
```

#### 3-2. 취약점만 초기화

```bash
psql "$DATABASE_URL" <<'SQL'
BEGIN;
TRUNCATE TABLE vulnerability_finding, vuln_current, vuln_snapshot RESTART IDENTITY;
COMMIT;
SQL
```

#### 3-3. 초기화 후 앱 재기동

```bash
pm2 restart finmonitor
pm2 restart blackbox
```

##### 간단 점검/개발용: 수동 실행

터미널 1:

```bash
./blackbox/blackbox_exporter --config.file=./blackbox/blackbox.yml --web.listen-address=0.0.0.0:9115
```

터미널 2:

```bash
npm start
```

### 종료 방법

#### PM2로 실행한 경우

```bash
pm2 delete all
```

#### 수동 실행한 경우

- `npm start`를 실행한 터미널에서 `Ctrl + C`
- `blackbox_exporter`를 실행한 터미널에서도 `Ctrl + C`

### 접속

```
http://localhost:3000
```

---

## 파일 구조

```
SocOpsASM/
├── blackbox/
│   ├── blackbox_exporter          # Prometheus Blackbox Exporter 바이너리
│   └── blackbox.yml               # 프로브 모듈 설정
├── src/
│   ├── server.js                  # Express 서버 진입점
│   ├── db.js                      # 가용성 모니터링 DB (PostgreSQL)
│   ├── routes.js                  # 가용성 모니터링 API 라우터
│   ├── blackbox.js                # Blackbox Exporter 호출 및 메트릭 파서
│   ├── scheduler.js               # node-cron 스케줄러 (1분마다 프로브)
│   ├── alerting.js                # nodemailer 알림 발송
│   ├── asm-db.js                  # ASM DB 스키마 및 시드 데이터 (PostgreSQL)
│   ├── asm-routes.js              # ASM API 라우터
│   ├── asm-pipeline.js            # 8단계 스캔 파이프라인 엔진
│   └── scanner.js                 # 스캔 유틸리티
├── public/
│   ├── index.html
│   └── static/
│       ├── app.js                 # 프론트엔드 SPA (Vanilla JS)
│       ├── styles.css             # Splunk 스타일 다크 UI
│       └── vendor/                # Chart.js, FontAwesome 로컬 번들
├── data/                          # (선택) 임시/보조 파일 디렉토리
│   └── (PostgreSQL 사용)          # 애플리케이션 데이터는 PostgreSQL 인스턴스에 저장
├── logs/                          # PM2 로그 (자동 생성)
├── ecosystem.config.cjs           # PM2 설정
├── .env.example                   # 환경변수 템플릿
└── package.json
```

---

## 등록 가능 금융사 (일괄 등록 지원)

- **금융기관**: 한국은행, 금융감독원, 금융위원회, 금융결제원, 예금보험공사, 한국거래소 등
- **은행**: KB국민, 신한, 우리, 하나, NH농협, IBK기업, 산업, 카카오뱅크, 케이뱅크, 토스뱅크
- **카드**: 신한, 삼성, 현대, KB국민, 롯데, 우리, 하나, BC
- **보험**: 한화생명, 삼성생명, 교보생명, 삼성화재, DB손해, 현대해상, KB손해, 메리츠화재 등
- **증권**: NH투자, 미래에셋, 삼성, KB, 키움, 한국투자, 신한, 카카오페이증권

---

## Blackbox Exporter 수집 메트릭

| 메트릭 | 설명 |
|--------|------|
| `probe_success` | UP/DOWN 여부 |
| `probe_duration_seconds` | 전체 응답시간 |
| `probe_http_status_code` | HTTP 상태코드 |
| `probe_http_ssl` | HTTPS 여부 |
| `probe_ssl_earliest_cert_expiry` | 인증서 만료 Unix timestamp |
| `probe_tls_version_info` | TLS 버전 (1.2/1.3) |
| `probe_http_duration_seconds{phase=*}` | 단계별 응답시간 (DNS/TCP/TLS/처리/전송) |

---

## Gmail SMTP 알림 설정

1. Google 계정 → 보안 → 2단계 인증 활성화
2. 앱 비밀번호 생성 (Gmail 선택)
3. `.env` 파일에 입력:

```env
SMTP_USER=your@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx
```

| 알림 유형 | 조건 | 내용 |
|-----------|------|------|
| 장애(DOWN) | probe_success=0 | 접속 불가 즉시 발송 |
| 복구 | DOWN → UP 전환 | 정상 복구 시 발송 |
| 응답지연 | > threshold_ms | 설정값 초과 시 발송 |
| SSL 만료임박 | < ssl_warn_days | 인증서 만료 D-30/14 경고 |

---

## 현재 구현 상태

### ✅ 완료

**가용성 모니터링**
- 실시간 대시보드 (카드·차트·모달)
- 수집 이력 7일 보관
- 대상 관리 CRUD + 금융사 일괄 등록
- Gmail 알림 (DOWN/복구/지연/SSL)

**블랙박스 공격 대시보드 (ASM)**
- 스캔 대상 관리 (IP 대역 CIDR / 도메인 등록·수정·삭제·활성화)
- 8단계 스캔 파이프라인 엔진 (Amass → Subfinder → dnsx → Naabu → Masscan → Nmap → httpx → Nuclei)
- 파이프라인 실시간 진행 상태 (3초 폴링, 단계별 progress bar)
- Raw Zone / Normalized Zone 이중 저장 구조
- 요약 대시보드 (6개 지표 카드, 심각도 분포, Top-10 포트, 위험 자산)
- 자산 인벤토리 (IP 우선 정렬, FQDN 그룹핑, 슬라이드 드로어)
- 취약점 현황 (인라인 상태 변경, CVE NVD 링크)
- 변경 이력 (Change Log)

### 🔧 추후 개선 가능 항목
- 스케줄 기반 자동 스캔 (cron)
- 일별 스냅샷 자동 생성
- 외부 취약점 DB 연동 (NVD API)
- 결과 리포트 PDF 내보내기
- 다중 조직 멀티테넌트 지원
