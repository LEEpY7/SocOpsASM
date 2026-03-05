# FinMonitor — 금융권 웹 가용성 모니터링

## 프로젝트 개요

SOC 담당자용 **외부 시점 웹 가용성 모니터링 시스템**.  
실제 Prometheus **Blackbox Exporter**를 통해 HTTP 프로브를 수행하며, 국내 전체 금융사를 한눈에 모니터링합니다.

## 아키텍처

```
[PM2]
  ├─ blackbox_exporter (port 9115)
  │     GET /probe?target=<url>&module=http_2xx
  │     → Prometheus text format 메트릭 반환
  └─ finmonitor (port 3000)
        → Blackbox 프로브 → better-sqlite3 (7일 보관) → 웹 UI
```

**완전 로컬 동작** (인터넷 불필요, CDN 없음):
- Node.js + Express
- better-sqlite3 (SQLite, 7일 데이터 보관)
- node-cron (1분마다 자동 프로브)
- nodemailer (Gmail SMTP 알림)
- Chart.js / FontAwesome 로컬 번들

## Blackbox Exporter 수집 메트릭

| 메트릭 | 설명 |
|--------|------|
| `probe_success` | UP/DOWN 여부 |
| `probe_duration_seconds` | 전체 응답시간 |
| `probe_http_status_code` | HTTP 상태코드 |
| `probe_http_version` | HTTP 버전 (1.1/2.0) |
| `probe_http_redirects` | 리다이렉트 횟수 |
| `probe_http_ssl` | HTTPS 여부 |
| `probe_ssl_earliest_cert_expiry` | 인증서 만료 Unix timestamp |
| `probe_tls_version_info` | TLS 버전 (1.2/1.3) |
| `probe_tls_cipher_info` | 암호화 스위트 |
| `probe_dns_lookup_time_seconds` | DNS 조회 시간 |
| `probe_http_duration_seconds{phase=resolve}` | DNS 단계 |
| `probe_http_duration_seconds{phase=connect}` | TCP 연결 단계 |
| `probe_http_duration_seconds{phase=tls}` | TLS 핸드셰이크 단계 |
| `probe_http_duration_seconds{phase=processing}` | 서버 처리 단계 |
| `probe_http_duration_seconds{phase=transfer}` | 데이터 전송 단계 |

## 메뉴 구성

| 메뉴 | 설명 |
|------|------|
| 실시간 대시보드 | 전체 현황 카드, 장애 알람 배너, 카테고리 탭, 타겟 카드 (클릭 시 상세 모달) |
| 수집 이력 (7일) | 가용률 테이블, 응답시간 통계, 24h 차트 |
| 대상 관리 | CRUD, 활성/비활성 토글, 국내 금융사 일괄 등록 (50+ 기관) |
| 알림 설정 | Gmail SMTP, DOWN/응답지연/SSL만료 알림 설정 |
| 알림 이력 | 발송 내역 조회 |

## 등록 가능 금융사 (일괄 등록 지원)

- **금융기관**: 한국은행, 금융감독원, 금융위원회, 금융결제원, 예금보험공사, 한국거래소 등
- **은행**: KB국민, 신한, 우리, 하나, NH농협, IBK기업, 산업, 카카오뱅크, 케이뱅크, 토스뱅크
- **카드**: 신한, 삼성, 현대, KB국민, 롯데, 우리, 하나, BC
- **보험**: 한화생명, 삼성생명, 교보생명, 삼성화재, DB손해, 현대해상, KB손해, 메리츠화재 등
- **증권**: NH투자, 미래에셋, 삼성, KB, 키움, 한국투자, 신한, 카카오페이증권

## 설치 및 실행 (로컬)

### 요구사항
- Node.js 18+
- npm

### 설치

```bash
git clone <repo>
cd finmonitor
npm install
```

### 환경변수 설정 (Gmail 알림 사용 시)

```bash
cp .env.example .env
# .env 파일 편집 — Gmail 앱 비밀번호 설정
```

### 실행

```bash
# PM2로 전체 서비스 기동 (Blackbox Exporter + FinMonitor 동시 실행)
pm2 start ecosystem.config.cjs

# 상태 확인
pm2 list
pm2 logs --nostream

# 서비스 중지
pm2 delete all
```

### 접속

```
http://localhost:3000
```

## 파일 구조

```
finmonitor/
├── blackbox/
│   ├── blackbox_exporter      # 바이너리 (linux-amd64 v0.25.0)
│   └── blackbox.yml           # 프로브 모듈 설정
├── src/
│   ├── server.js              # Express 서버 진입점
│   ├── blackbox.js            # Blackbox Exporter 호출 및 메트릭 파서
│   ├── db.js                  # SQLite 스키마 및 DB 초기화
│   ├── routes.js              # API 라우터
│   ├── scheduler.js           # node-cron 스케줄러
│   └── alerting.js            # nodemailer 알림 발송
├── public/
│   ├── index.html
│   └── static/
│       ├── app.js             # 프론트엔드 SPA (Vanilla JS)
│       ├── styles.css         # Splunk 스타일 다크 UI
│       └── vendor/            # 로컬 번들 (Chart.js, FontAwesome)
├── data/                      # SQLite DB (자동 생성)
├── logs/                      # PM2 로그 (자동 생성)
├── ecosystem.config.cjs       # PM2 설정
├── .env.example               # 환경변수 템플릿
└── package.json
```

## Gmail SMTP 설정

1. Google 계정 → 보안 → 2단계 인증 활성화
2. 앱 비밀번호 생성 (Gmail 선택)
3. `.env` 파일에 입력:

```
SMTP_USER=your@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx
```

## 알림 유형

| 유형 | 조건 | 설명 |
|------|------|------|
| 장애(DOWN) | probe_success=0 | 접속 불가 즉시 발송 |
| 복구 | DOWN → UP 전환 | 정상 복구 시 발송 |
| 응답지연 | > threshold_ms | 설정값 초과 시 발송 |
| SSL 만료임박 | < ssl_warn_days | 인증서 만료 D-30/14 경고 |

## 기술 스택

| 구분 | 기술 |
|------|------|
| 프로브 | Blackbox Exporter v0.25.0 |
| 백엔드 | Node.js + Express |
| DB | SQLite (better-sqlite3) |
| 스케줄러 | node-cron |
| 알림 | nodemailer (Gmail SMTP) |
| 프론트엔드 | Vanilla JS SPA |
| 차트 | Chart.js (로컬 번들) |
| 아이콘 | FontAwesome (로컬 번들) |
| 프로세스 관리 | PM2 |
