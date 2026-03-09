/* =========================================================
   FinMonitor — app.js
   순수 Vanilla JS / 로컬 Node.js + Blackbox Exporter 100% 연동
   ========================================================= */

'use strict'

// ─── 상수 & 상태 ────────────────────────────────────────────
const API = '/api'

const state = {
  page: 'dashboard',
  status: null,       // /api/status 응답
  historySummary: [], // /api/history-summary 응답
  targets: [],        // /api/targets 응답
  alerts: [],         // /api/alerts 응답
  categories: [],     // /api/categories 응답
  activeCategory: 'all',
  autoRefresh: true,
  refreshInterval: 60,
  lastRefresh: null,
  refreshTimer: null,
  probing: new Set(),
  // 대시보드 상단 차트
  dashboardChartTargetId: null,
  dashboardChartData: [],
  dashboardChartObj: null,
  // 공격 대시보드 (ASM)
  attackSummary:   null,
  attackInventory: null,   // { total, page, limit, items[] }
  attackVulns:     null,   // { total, page, limit, items[] }
  attackAssets:    [],     // 구버전 attack_assets (호환용)
}

const CAT_META = {
  all:        { label: '전체',      icon: 'fa-solid fa-layer-group',     color: '#5b70f5' },
  hanwha:     { label: '한화생명',   icon: 'fa-solid fa-fire-flame-curved', color: '#ff6b2b' },
  institution:{ label: '금융기관',   icon: 'fa-solid fa-landmark',        color: '#3b82f6' },
  bank:       { label: '은행',      icon: 'fa-solid fa-building-columns', color: '#22c55e' },
  card:       { label: '카드',      icon: 'fa-solid fa-credit-card',     color: '#a855f7' },
  insurance:  { label: '보험',      icon: 'fa-solid fa-shield-halved',   color: '#f97316' },
  securities: { label: '증권',      icon: 'fa-solid fa-chart-line',      color: '#f59e0b' },
  other:      { label: '기타',      icon: 'fa-solid fa-link',            color: '#8a8fa8' }
}

// ─── 초기화 ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  buildLayout()
  navigate('dashboard')
  checkBlackboxHealth()
  setInterval(checkBlackboxHealth, 30000)
})

// ─── 레이아웃 구성 ───────────────────────────────────────────
function buildLayout() {
  document.getElementById('app').innerHTML = `
  <div id="app-layout">
    <!-- 사이드바 -->
    <nav id="sidebar">
      <div class="sidebar-logo">
        <div class="logo-icon">
          <img src="/static/img/hanwhalife.png" alt="한화생명 CI">
        </div>
        <div>
          <div class="logo-text">한화생명 보안관제센터</div>
          <div class="logo-sub">HanwhaLife Cyber Security Center</div>
        </div>
      </div>

      <!-- ① 가용성 모니터링 -->
      <div class="sidebar-section">
        <div class="sidebar-section-title">
          <i class="fa-solid fa-signal" style="margin-right:5px;color:#22c55e"></i>가용성 모니터링
        </div>
        <div class="nav-item active" data-page="dashboard" onclick="navigate('dashboard')">
          <i class="fa-solid fa-gauge-high"></i> 실시간 대시보드
          <span id="nav-badge-down" class="nav-badge" style="display:none">0</span>
        </div>
        <div class="nav-item" data-page="history" onclick="navigate('history')">
          <i class="fa-solid fa-clock-rotate-left"></i> 수집 이력
        </div>
        <div class="nav-item" data-page="targets" onclick="navigate('targets')">
          <i class="fa-solid fa-list-check"></i> 대상 관리
        </div>
      </div>

      <!-- ② 블랙박스 공격 대시보드 -->
      <div class="sidebar-section">
        <div class="sidebar-section-title">
          <i class="fa-solid fa-shield-virus" style="margin-right:5px;color:#ef4444"></i>블랙박스 공격 대시보드
        </div>
        <div class="nav-item" data-page="attack-dashboard" onclick="navigate('attack-dashboard')">
          <i class="fa-solid fa-chart-line"></i> 요약 대시보드
        </div>
        <div class="nav-item" data-page="attack-assets" onclick="navigate('attack-assets')">
          <i class="fa-solid fa-server"></i> 자산 인벤토리
        </div>
        <div class="nav-item" data-page="attack-vulns" onclick="navigate('attack-vulns')">
          <i class="fa-solid fa-bug"></i> 취약점 현황
        </div>
      </div>

      <!-- ③ 경보 관리 -->
      <div class="sidebar-section">
        <div class="sidebar-section-title">
          <i class="fa-solid fa-bell" style="margin-right:5px;color:#f59e0b"></i>경보 관리
        </div>
        <div class="nav-item" data-page="alertconf" onclick="navigate('alertconf')">
          <i class="fa-solid fa-sliders"></i> 알림 설정
          <span id="nav-badge-alert" class="nav-badge info" style="display:none">!</span>
        </div>
        <div class="nav-item" data-page="alertlog" onclick="navigate('alertlog')">
          <i class="fa-solid fa-envelope-open-text"></i> 알림 이력
        </div>
      </div>

      <div class="sidebar-footer">
        <div class="bb-status" id="bb-status">
          <div class="dot"></div>
          <span id="bb-status-text">Blackbox 연결 확인 중…</span>
        </div>
        <div id="bb-url" style="font-size:10px;color:#5a5f78;margin-top:2px"></div>
      </div>
    </nav>

    <!-- 메인 -->
    <div id="main-wrap">
      <!-- 상단 바 -->
      <div id="topbar">
        <div class="topbar-left">
          <span class="topbar-module-badge" id="topbar-module-badge"></span>
          <div class="topbar-title" id="topbar-title">실시간 대시보드</div>
        </div>
        <div class="topbar-actions">
          <span id="last-refresh-time"></span>
          <div class="auto-refresh-wrap">
            <label class="toggle-switch">
              <input type="checkbox" id="auto-refresh-toggle" checked
                onchange="toggleAutoRefresh(this.checked)">
              <span class="toggle-track"></span>
            </label>
            자동
          </div>
          <button class="btn btn-secondary btn-sm" onclick="manualRefresh()">
            <i class="fa-solid fa-rotate-right"></i> 새로고침
          </button>
          <!-- 전체 프로브: 가용성 모니터링 페이지에서만 표시 -->
          <button class="btn btn-primary btn-sm" id="btn-probe-all"
                  onclick="probeAll()" style="display:none">
            <i class="fa-solid fa-bolt"></i> 전체 프로브
          </button>
        </div>
      </div>

      <!-- 콘텐츠 -->
      <div id="content"></div>
    </div>
  </div>
  <div id="toast-container"></div>
  `
}

// ─── 네비게이션 ─────────────────────────────────────────────
// 모듈 그룹 정의 — topbar 배지 색상 및 레이블
const MODULE_META = {
  dashboard:        { module: 'availability', label: '가용성 모니터링',       color: '#22c55e' },
  history:          { module: 'availability', label: '가용성 모니터링',       color: '#22c55e' },
  targets:          { module: 'availability', label: '가용성 모니터링',       color: '#22c55e' },
  'attack-dashboard': { module: 'attack',    label: '블랙박스 공격 대시보드', color: '#ef4444' },
  'attack-assets':    { module: 'attack',    label: '블랙박스 공격 대시보드', color: '#ef4444' },
  'attack-vulns':     { module: 'attack',    label: '블랙박스 공격 대시보드', color: '#ef4444' },
  alertconf:        { module: 'alert',        label: '경보 관리',             color: '#f59e0b' },
  alertlog:         { module: 'alert',        label: '경보 관리',             color: '#f59e0b' },
}

const PAGE_TITLES = {
  dashboard:          '실시간 대시보드',
  history:            '수집 이력 (7일)',
  targets:            '대상 관리',
  'attack-dashboard': '요약 대시보드',
  'attack-assets':    '자산 인벤토리',
  'attack-vulns':     '취약점 현황',
  alertconf:          '알림 설정',
  alertlog:           '알림 이력',
}

// 가용성 모니터링 페이지 목록 (전체 프로브 버튼 표시 대상)
const AVAIL_PAGES = new Set(['dashboard', 'history', 'targets'])

async function navigate(page) {
  state.page = page
  clearInterval(state.refreshTimer)

  // 사이드바 active
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page)
  })

  // topbar 모듈 배지 + 제목
  const meta = MODULE_META[page] || { label: '', color: '#5b70f5' }
  const badge = document.getElementById('topbar-module-badge')
  if (badge) {
    badge.textContent = meta.label
    badge.style.background = meta.color + '22'
    badge.style.color       = meta.color
    badge.style.borderColor = meta.color + '55'
  }
  document.getElementById('topbar-title').textContent = PAGE_TITLES[page] || page

  // 전체 프로브 버튼: 가용성 모니터링 그룹에서만 표시
  const btnProbe = document.getElementById('btn-probe-all')
  if (btnProbe) btnProbe.style.display = AVAIL_PAGES.has(page) ? '' : 'none'

  const content = document.getElementById('content')
  content.innerHTML = `<div class="loading-overlay"><div class="spinner"></div><span>데이터 로드 중…</span></div>`

  try {
    switch (page) {
      case 'dashboard':
        await loadAll(); renderDashboard(); startAutoRefresh(); break
      case 'history':
        await loadAll(); renderHistory(); break
      case 'targets':
        await fetchTargets(); renderTargets(); break
      case 'attack-dashboard':
        await loadAttackSummary(); renderAttackDashboard(); break
      case 'attack-assets':
        await loadAndRenderInventory(1); break
      case 'attack-vulns':
        await loadAndRenderVulns(1); break
      case 'alertconf':
        await fetchAlerts(); renderAlertConf(); break
      case 'alertlog':
        renderAlertLog(); break
    }
  } catch (err) {
    content.innerHTML = `<div class="empty-state">
      <i class="fa-solid fa-triangle-exclamation" style="color:var(--red)"></i>
      <h3>데이터 로드 오류</h3>
      <p>${err.message}</p>
    </div>`
    toast('오류: ' + err.message, 'error')
  }
}

// ─── API 헬퍼 ────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error || `HTTP ${res.status}`)
  }
  return res.json()
}

// ─── 데이터 로더 ────────────────────────────────────────────
async function loadAll() {
  const [status, summary, cats] = await Promise.all([
    api('/status'),
    api('/history-summary'),
    api('/categories')
  ])
  state.status = status
  state.historySummary = summary
  state.categories = cats
  state.lastRefresh = new Date()
  updateLastRefreshUI()
  updateNavBadges()

  // 대시보드 차트 대상: 한화생명 대표홈페이지(category=hanwha, sub_category=대표사이트) 고정
  // — 최초 1회만 탐색하고 이후 고정 유지
  if (!state.dashboardChartTargetId && status.targets && status.targets.length > 0) {
    const hanwha = status.targets.find(t => t.category === 'hanwha' && t.sub_category === '대표사이트')
                || status.targets.find(t => t.category === 'hanwha')
                || status.targets[0]
    state.dashboardChartTargetId = hanwha.id
  }

  // 차트 데이터 갱신 — 3시간 / 최대 180포인트
  if (state.dashboardChartTargetId) {
    try {
      state.dashboardChartData = await api(`/history-chart/${state.dashboardChartTargetId}?hours=3`)
    } catch { state.dashboardChartData = [] }
  }
}

async function fetchTargets() {
  state.targets = await api('/targets')
  state.lastRefresh = new Date()
}

async function fetchAlerts() {
  state.alerts = await api('/alerts')
  state.lastRefresh = new Date()
}

function updateLastRefreshUI() {
  const el = document.getElementById('last-refresh-time')
  if (el && state.lastRefresh) {
    el.textContent = state.lastRefresh.toLocaleTimeString('ko-KR')
  }
}

function updateNavBadges() {
  if (!state.status) return
  const downN = state.status.summary.down
  const badge = document.getElementById('nav-badge-down')
  if (badge) {
    badge.textContent = downN
    badge.style.display = downN > 0 ? '' : 'none'
  }

  // 알림 설정 미등록 시 느낌표
  const alertBadge = document.getElementById('nav-badge-alert')
  if (alertBadge) {
    const noAlert = state.alerts.length === 0
    alertBadge.style.display = noAlert ? '' : 'none'
  }
}

// ─── Blackbox 헬스체크 ────────────────────────────────────────
async function checkBlackboxHealth() {
  try {
    const data = await api('/health')
    const el = document.getElementById('bb-status')
    const txt = document.getElementById('bb-status-text')
    const urlEl = document.getElementById('bb-url')
    if (el && txt) {
      if (data.blackbox && data.blackbox.ok) {
        el.className = 'bb-status ok'
        txt.textContent = 'Blackbox 연결됨'
      } else {
        el.className = 'bb-status err'
        txt.textContent = 'Blackbox 연결 실패'
      }
      if (urlEl && data.blackbox) urlEl.textContent = data.blackbox.url
    }
  } catch {}
}

// ─── 자동 새로고침 ────────────────────────────────────────────
function startAutoRefresh() {
  clearInterval(state.refreshTimer)
  if (!state.autoRefresh) return
  state.refreshTimer = setInterval(async () => {
    if (state.page !== 'dashboard') return
    await loadAll()
    renderDashboard()
  }, state.refreshInterval * 1000)
}

function toggleAutoRefresh(on) {
  state.autoRefresh = on
  if (on) startAutoRefresh()
  else clearInterval(state.refreshTimer)
}

async function manualRefresh() {
  if (state.page === 'dashboard')        { await loadAll(); renderDashboard() }
  else if (state.page === 'history')     { await loadAll(); renderHistory() }
  else if (state.page === 'targets')     { await fetchTargets(); renderTargets() }
  else if (state.page === 'attack-dashboard') { await loadAttackSummary(); renderAttackDashboard() }
  else if (state.page === 'attack-assets')    { await loadAndRenderInventory() }
  else if (state.page === 'attack-vulns')     { await loadAndRenderVulns() }
  else if (state.page === 'alertconf')   { await fetchAlerts(); renderAlertConf() }
  else if (state.page === 'alertlog')    { renderAlertLog() }
}

// ─── ASM 데이터 로더 ─────────────────────────────────────────
async function loadAttackSummary() {
  state.attackSummary = await api('/asm/summary')
  state.lastRefresh = new Date(); updateLastRefreshUI()
}
async function loadAttackInventory(params = '') {
  const data = await api('/asm/inventory?' + params)
  state.attackInventory = data
  state.lastRefresh = new Date(); updateLastRefreshUI()
}
async function loadAttackVulns(params = '') {
  const data = await api('/asm/vulns?' + params)
  state.attackVulns = data
  state.lastRefresh = new Date(); updateLastRefreshUI()
}
async function loadAttackAssets() {
  state.attackAssets = await api('/attack/assets')
  state.lastRefresh = new Date(); updateLastRefreshUI()
}

// ─── 토스트 ──────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const icons = { info: 'fa-circle-info', success: 'fa-circle-check', error: 'fa-circle-xmark', warn: 'fa-triangle-exclamation' }
  const el = document.createElement('div')
  el.className = `toast ${type}`
  el.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span class="toast-msg">${msg}</span>`
  document.getElementById('toast-container').appendChild(el)
  setTimeout(() => el.remove(), 3500)
}

// ──────────────────────────────────────────────────────────────
// 1. 실시간 대시보드
// ──────────────────────────────────────────────────────────────
function renderDashboard() {
  if (!state.status) return
  const { summary, targets } = state.status

  const downTargets = targets.filter(t => t.probe_time && t.probe_success === 0)

  // 현재 선택된 대상 정보 (한화생명 대표홈페이지 고정)
  const chartTarget = targets.find(t => t.id === state.dashboardChartTargetId)
  const chartSummary = state.historySummary.find(h => h.id === state.dashboardChartTargetId)
  const upCnt  = state.dashboardChartData.filter(r => r.probe_success === 1).length
  const pct3h  = state.dashboardChartData.length > 0
    ? ((upCnt / state.dashboardChartData.length) * 100).toFixed(1) : '-'
  const avgMs  = state.dashboardChartData.filter(r => r.probe_duration_ms).reduce((a, r, _, arr) =>
    a + r.probe_duration_ms / arr.length, 0)
  const minMs  = state.dashboardChartData.reduce((m, r) => r.probe_duration_ms ? Math.min(m, r.probe_duration_ms) : m, Infinity)
  const maxMs  = state.dashboardChartData.reduce((m, r) => r.probe_duration_ms ? Math.max(m, r.probe_duration_ms) : m, 0)

  const content = document.getElementById('content')
  content.innerHTML = `

    <!-- ★ 대시보드 상단 응답시간 차트 패널 -->
    <div class="panel dash-top-chart-panel" style="margin-bottom:20px">
      <div class="panel-header">
        <div class="panel-title">
          <i class="fa-solid fa-chart-bar"></i>
          <span>한화생명 대표홈페이지</span>
          <span style="font-size:11px;font-weight:400;color:var(--text-muted);margin-left:6px">— 3시간 응답시간 추이</span>
        </div>
        <button class="btn btn-icon btn-sm" onclick="refreshDashChart()" title="차트 새로고침">
          <i class="fa-solid fa-rotate-right"></i>
        </button>
      </div>

      <!-- 상단 미니 통계 바 -->
      <div class="dash-chart-stats" id="dash-chart-stats">
        ${chartTarget ? `
          <div class="dc-stat">
            <span class="dc-label">현재상태</span>
            <span class="dc-value ${chartTarget.probe_success === 1 ? 'green' : (chartTarget.probe_time ? 'red' : '')}">
              ${chartTarget.probe_success === 1 ? '● UP' : (chartTarget.probe_time ? '● DOWN' : '─ 미점검')}
            </span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">HTTP</span>
            <span class="dc-value">${chartTarget.http_status_code || '-'}</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">3h 가용률</span>
            <span class="dc-value ${parseFloat(pct3h) >= 99 ? 'green' : (parseFloat(pct3h) >= 95 ? 'yellow' : 'red')}">${pct3h}%</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">평균 응답</span>
            <span class="dc-value blue">${avgMs > 0 ? Math.round(avgMs) + ' ms' : '-'}</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">최소</span>
            <span class="dc-value">${isFinite(minMs) ? Math.round(minMs) + ' ms' : '-'}</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">최대</span>
            <span class="dc-value ${maxMs > 3000 ? 'red' : ''}">${maxMs > 0 ? Math.round(maxMs) + ' ms' : '-'}</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">TLS</span>
            <span class="dc-value">${chartTarget.tls_version || '-'}</span>
          </div>
          <div class="dc-stat">
            <span class="dc-label">SSL 만료</span>
            <span class="dc-value ${chartTarget.ssl_expiry_days < 14 ? 'red' : (chartTarget.ssl_expiry_days < 30 ? 'yellow' : '')}">
              ${chartTarget.ssl_expiry_days != null ? chartTarget.ssl_expiry_days + '일' : '-'}
            </span>
          </div>
        ` : '<span style="color:var(--text-muted);font-size:12px">데이터 로드 중…</span>'}
      </div>

      <!-- 차트 캔버스 -->
      <div class="panel-body no-pad" style="padding:0 16px 16px">
        <div class="chart-wrap" style="height:200px;background:var(--bg-panel);border-radius:0">
          <canvas id="dash-top-chart" style="height:200px"></canvas>
        </div>
        <div style="display:flex;align-items:center;gap:16px;margin-top:8px;font-size:10px;color:var(--text-muted);padding:0 4px">
          <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(34,197,94,0.8);margin-right:4px"></span>UP</span>
          <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:rgba(239,68,68,0.8);margin-right:4px"></span>DOWN</span>
          <span style="margin-left:auto">${state.dashboardChartData.length}개 포인트 (최근 3시간 · 1분당 1포인트)</span>
        </div>
      </div>
    </div>

    ${downTargets.length > 0 ? renderAlertBanner(downTargets) : ''}

    <!-- 요약 카드 -->
    <div class="summary-grid">
      ${statCard('total', '모니터링 대상', summary.total, '', 'fa-solid fa-server')}
      ${statCard('up', '정상 (UP)', summary.up, 'green', 'fa-solid fa-circle-check')}
      ${statCard('down', '장애 (DOWN)', summary.down, summary.down > 0 ? 'red' : '', 'fa-solid fa-circle-xmark')}
      ${statCard('warn', '미확인', summary.no_data, '', 'fa-solid fa-circle-question')}
      ${statCard('resp', '평균 응답', summary.avg_response_ms ? summary.avg_response_ms + ' ms' : '-', 'blue', 'fa-solid fa-gauge')}
      ${statCard('ssl', 'SSL 경고', summary.ssl_warnings, summary.ssl_warnings > 0 ? 'yellow' : '', 'fa-solid fa-lock')}
    </div>

    <!-- 카테고리 탭 -->
    ${renderCatTabs(targets)}

    <!-- 타겟 카드 목록 -->
    <div id="target-content">
      ${renderTargetsByCategory(targets)}
    </div>
  `

  updateLastRefreshUI()

  // 차트 그리기 (DOM 생성 직후)
  renderDashTopChart(state.dashboardChartData)
}

function statCard(cls, label, value, color, icon) {
  return `
    <div class="stat-card ${cls}">
      <div class="stat-label"><i class="${icon}" style="margin-right:4px"></i>${label}</div>
      <div class="stat-value ${color}">${value ?? '-'}</div>
    </div>
  `
}

// ─── 대시보드 상단 차트 렌더링 ──────────────────────────────
function renderDashTopChart(data) {
  const canvas = document.getElementById('dash-top-chart')
  if (!canvas) return

  // 기존 인스턴스 파괴
  if (state.dashboardChartObj) {
    state.dashboardChartObj.destroy()
    state.dashboardChartObj = null
  }

  if (!data || data.length === 0) {
    const ctx = canvas.getContext('2d')
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    // 빈 상태 텍스트
    canvas.parentElement.insertAdjacentHTML('beforeend',
      '<div id="dash-chart-empty" style="text-align:center;color:var(--text-muted);font-size:12px;padding:8px">수집된 데이터가 없습니다. 잠시 후 자동으로 업데이트됩니다.</div>')
    return
  }

  // 빈 상태 메시지 제거
  const emptyEl = document.getElementById('dash-chart-empty')
  if (emptyEl) emptyEl.remove()

  const labels    = data.map(r => fmtChartTime(r.probe_time))
  const resps     = data.map(r => r.probe_duration_ms ? Math.round(r.probe_duration_ms) : 0)
  const bgColors  = data.map(r => r.probe_success === 1 ? 'rgba(34,197,94,0.75)' : 'rgba(239,68,68,0.85)')
  const brdColors = data.map(r => r.probe_success === 1 ? 'rgba(34,197,94,1)'    : 'rgba(239,68,68,1)')

  // 이동평균선 (5점)
  const movAvg = resps.map((_, i, arr) => {
    const w = 5
    const start = Math.max(0, i - Math.floor(w / 2))
    const end   = Math.min(arr.length, start + w)
    const slice = arr.slice(start, end).filter(v => v > 0)
    return slice.length > 0 ? Math.round(slice.reduce((a, v) => a + v, 0) / slice.length) : null
  })

  state.dashboardChartObj = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: '응답시간 (ms)',
          data: resps,
          backgroundColor: bgColors,
          borderColor: brdColors,
          borderWidth: 1,
          borderRadius: 3,
          order: 2
        },
        {
          label: '이동평균 (5점)',
          data: movAvg,
          type: 'line',
          borderColor: 'rgba(91,112,245,0.9)',
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
          tension: 0.35,
          order: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          display: true,
          position: 'top',
          align: 'end',
          labels: {
            color: '#8a8fa8', font: { size: 11 },
            boxWidth: 12, boxHeight: 8, padding: 12,
            filter: item => item.text !== '응답시간 (ms)'  // 바 범례는 아래 커스텀 표기 사용
          }
        },
        tooltip: {
          backgroundColor: '#22252f',
          borderColor: '#353849',
          borderWidth: 1,
          titleColor: '#d4d6e0',
          bodyColor: '#8a8fa8',
          padding: 10,
          callbacks: {
            title: ctx => ctx[0].label,
            label: ctx => {
              if (ctx.datasetIndex === 1) return `  이동평균: ${ctx.raw ?? '-'} ms`
              const r = data[ctx.dataIndex]
              const lines = [`  응답시간: ${ctx.raw} ms`, `  상태: ${r.probe_success ? '✓ UP' : '✗ DOWN'}`]
              if (r.http_status_code)       lines.push(`  HTTP: ${r.http_status_code}`)
              if (r.dns_lookup_ms)           lines.push(`  DNS: ${Math.round(r.dns_lookup_ms)} ms`)
              if (r.http_duration_tls_ms)    lines.push(`  TLS: ${Math.round(r.http_duration_tls_ms)} ms`)
              if (r.ssl_expiry_days != null)  lines.push(`  SSL 만료: ${r.ssl_expiry_days}일`)
              if (r.error_msg)               lines.push(`  오류: ${r.error_msg}`)
              return lines
            }
          }
        }
      },
      scales: {
        x: {
          ticks: {
            color: '#8a8fa8',
            maxTicksLimit: 15,
            maxRotation: 0,
            font: { size: 10 }
          },
          grid: { color: 'rgba(53,56,73,0.6)' }
        },
        y: {
          ticks: { color: '#8a8fa8', font: { size: 10 } },
          grid: { color: 'rgba(53,56,73,0.6)' },
          beginAtZero: true,
          title: {
            display: true,
            text: 'ms',
            color: '#5a5f78',
            font: { size: 10 }
          }
        }
      }
    }
  })
}

// 차트용 시간 포맷 (MM/DD HH:mm)
function fmtChartTime(str) {
  if (!str) return ''
  const d = new Date(str)
  if (isNaN(d)) return str
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  const mi = String(d.getMinutes()).padStart(2, '0')
  return `${mm}/${dd} ${hh}:${mi}`
}

// 대시보드 차트 대상 변경
async function changeDashChartTarget(id) {
  if (!id || id === state.dashboardChartTargetId) return
  state.dashboardChartTargetId = id

  // 로딩 표시
  const canvas = document.getElementById('dash-top-chart')
  if (canvas) {
    if (state.dashboardChartObj) { state.dashboardChartObj.destroy(); state.dashboardChartObj = null }
    canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height)
  }

  try {
    state.dashboardChartData = await api(`/history-chart/${id}?hours=3`)
  } catch { state.dashboardChartData = [] }

  // 통계 바 & 차트 업데이트 (전체 재렌더 없이 부분만 갱신)
  updateDashChartStatsUI()
  renderDashTopChart(state.dashboardChartData)
}

// 통계 바만 갱신
function updateDashChartStatsUI() {
  const statsEl = document.getElementById('dash-chart-stats')
  if (!statsEl || !state.status) return

  const targets = state.status.targets
  const t = targets.find(x => x.id === state.dashboardChartTargetId)
  if (!t) return

  const data = state.dashboardChartData
  const upCnt = data.filter(r => r.probe_success === 1).length
  const pct   = data.length > 0 ? ((upCnt / data.length) * 100).toFixed(1) : '-'
  const avgMs = data.filter(r => r.probe_duration_ms).reduce((a, r, _, arr) => a + r.probe_duration_ms / arr.length, 0)
  const minMs = data.reduce((m, r) => r.probe_duration_ms ? Math.min(m, r.probe_duration_ms) : m, Infinity)
  const maxMs = data.reduce((m, r) => r.probe_duration_ms ? Math.max(m, r.probe_duration_ms) : m, 0)

  statsEl.innerHTML = `
    <div class="dc-stat">
      <span class="dc-label">현재상태</span>
      <span class="dc-value ${t.probe_success === 1 ? 'green' : (t.probe_time ? 'red' : '')}">
        ${t.probe_success === 1 ? '● UP' : (t.probe_time ? '● DOWN' : '─ 미점검')}
      </span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">HTTP</span>
      <span class="dc-value">${t.http_status_code || '-'}</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">3h 가용률</span>
      <span class="dc-value ${parseFloat(pct) >= 99 ? 'green' : (parseFloat(pct) >= 95 ? 'yellow' : 'red')}">${pct}%</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">평균 응답</span>
      <span class="dc-value blue">${avgMs > 0 ? Math.round(avgMs) + ' ms' : '-'}</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">최소</span>
      <span class="dc-value">${isFinite(minMs) ? Math.round(minMs) + ' ms' : '-'}</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">최대</span>
      <span class="dc-value ${maxMs > 3000 ? 'red' : ''}">${maxMs > 0 ? Math.round(maxMs) + ' ms' : '-'}</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">TLS</span>
      <span class="dc-value">${t.tls_version || '-'}</span>
    </div>
    <div class="dc-stat">
      <span class="dc-label">SSL 만료</span>
      <span class="dc-value ${t.ssl_expiry_days < 14 ? 'red' : (t.ssl_expiry_days < 30 ? 'yellow' : '')}">
        ${t.ssl_expiry_days != null ? t.ssl_expiry_days + '일' : '-'}
      </span>
    </div>
  `
}

// 차트만 강제 새로고침 (버튼 클릭)
async function refreshDashChart() {
  if (!state.dashboardChartTargetId) return
  try {
    state.dashboardChartData = await api(`/history-chart/${state.dashboardChartTargetId}?hours=3`)
  } catch { state.dashboardChartData = [] }
  updateDashChartStatsUI()
  renderDashTopChart(state.dashboardChartData)
  toast('차트 업데이트 완료', 'success')
}

function renderAlertBanner(downTargets) {
  const items = downTargets.map(t => `
    <div class="alert-item">
      <i class="fa-solid fa-circle-xmark" style="color:var(--red)"></i>
      <span class="a-name">${esc(t.name)}</span>
      <span class="a-err">${esc(t.error_msg || 'HTTP ' + (t.http_status_code || '-'))}</span>
      <span class="a-time">${fmtTime(t.probe_time)}</span>
      <button class="btn btn-xs btn-danger" onclick="probeOne(${t.id})">재프로브</button>
    </div>
  `).join('')

  return `
    <div class="alert-banner">
      <div class="alert-banner-title">
        <i class="fa-solid fa-siren-on"></i>
        현재 장애 감지 — ${downTargets.length}개 대상 접속 불가
      </div>
      ${items}
    </div>
  `
}

// 탭 고정 순서: 전체 → 한화생명 → 금융기관 → 은행 → 카드 → 보험 → 증권 → 기타
const CAT_ORDER = ['all', 'hanwha', 'institution', 'bank', 'card', 'insurance', 'securities', 'other']

function renderCatTabs(targets) {
  const counts = {}
  for (const t of targets) {
    counts[t.category] = (counts[t.category] || 0) + 1
  }

  // 고정 순서로 탭 생성 (대상 있는 카테고리만 표시, 전체는 항상 표시)
  const tabs = CAT_ORDER
    .filter(k => k === 'all' || counts[k])
    .map(k => {
      const meta = CAT_META[k]
      const cnt  = k === 'all' ? targets.length : counts[k]
      return { k, label: meta.label, icon: meta.icon, cnt }
    })

  return `
    <div class="cat-tabs" id="cat-tabs">
      ${tabs.map(({ k, label, icon, cnt }) => `
        <div class="cat-tab ${state.activeCategory === k ? 'active' : ''}"
             data-cat="${k}" onclick="setCat('${k}')">
          <i class="${icon}"></i>
          ${label}
          <span class="tab-count">${cnt}</span>
        </div>
      `).join('')}
    </div>
  `
}

function setCat(cat) {
  state.activeCategory = cat
  // data-cat 속성으로 정확히 active 전환
  document.querySelectorAll('.cat-tab').forEach(el => {
    el.classList.toggle('active', el.dataset.cat === cat)
  })
  // 타겟 카드 재렌더
  const filtered = cat === 'all'
    ? state.status.targets
    : state.status.targets.filter(t => t.category === cat)
  document.getElementById('target-content').innerHTML = renderTargetsByCategory(filtered, true)
}

function renderTargetsByCategory(targets, flat = false) {
  if (targets.length === 0) return `<div class="empty-state"><i class="fa-solid fa-radar"></i><h3>대상 없음</h3><p>대상 관리에서 금융사를 추가하세요.</p></div>`

  if (flat) {
    return `<div class="target-grid">${targets.map(renderTargetCard).join('')}</div>`
  }

  // CAT_ORDER 순서로 카테고리 그룹 렌더
  const groups = {}
  for (const t of targets) {
    if (!groups[t.category]) groups[t.category] = []
    groups[t.category].push(t)
  }

  return CAT_ORDER.filter(cat => groups[cat] && groups[cat].length > 0).map(cat => {
    const rows = groups[cat]
    const meta = CAT_META[cat] || CAT_META.other
    const up   = rows.filter(r => r.probe_success === 1).length
    const down = rows.filter(r => r.probe_time && r.probe_success === 0).length
    return `
      <div class="cat-section">
        <div class="cat-section-header">
          <div class="cat-section-title" style="color:${meta.color}">
            <i class="${meta.icon}"></i> ${meta.label}
          </div>
          <div class="cat-stat">
            <span class="up-n">${up} UP</span>
            ${down > 0 ? `<span class="down-n">${down} DOWN</span>` : ''}
            <span>/ ${rows.length} 대상</span>
          </div>
        </div>
        <div class="target-grid">
          ${rows.map(renderTargetCard).join('')}
        </div>
      </div>
    `
  }).join('')
}

function renderTargetCard(t) {
  const isUp    = t.probe_success === 1
  const isDown  = t.probe_time && t.probe_success === 0
  const noData  = !t.probe_time

  const statusClass = isUp ? 'up' : (isDown ? 'down' : 'nodata')
  const cardClass   = isDown ? 'is-down' : (noData ? 'no-data' : '')

  // 응답속도 색상
  let respClass = ''
  const resp = t.probe_duration_ms
  if (resp) {
    if (resp < 800)  respClass = 'fast'
    else if (resp < 2000) respClass = 'medium'
    else respClass = 'slow'
  }

  // SSL 배지
  let sslBadge = ''
  if (t.ssl_expiry_days !== null) {
    const cls = t.ssl_expiry_days < 14 ? 'ssl-crit' : (t.ssl_expiry_days < 30 ? 'ssl-warn' : 'ssl-ok')
    sslBadge = `<span class="badge badge-${cls}"><i class="fa-solid fa-lock"></i> SSL ${t.ssl_expiry_days}일</span>`
  }

  // 업타임 바 (historySummary 데이터 활용)
  const uptimePct = getUptimePct(t.id)

  const summary = state.historySummary.find(h => h.id === t.id)
  const checks  = summary ? summary.total_checks : 0

  return `
    <div class="target-card ${cardClass}" onclick="showDetail(${t.id})"
         title="${esc(t.url)}">
      <div class="tc-head">
        <div class="tc-status-dot ${statusClass}"></div>
        <div>
          <div class="tc-name">${esc(t.name)}</div>
          <div class="tc-sub">${esc(t.sub_category || t.category)}</div>
        </div>
        ${state.probing.has(t.id) ? '<div class="spinner" style="margin-left:auto"></div>' : ''}
      </div>

      <div class="tc-badges">
        <span class="badge badge-${statusClass === 'nodata' ? 'nodata' : (isUp ? 'up' : 'down')}">
          ${isUp ? '✓ UP' : (isDown ? '✗ DOWN' : '─ 미점검')}
        </span>
        ${t.http_status_code ? `<span class="badge badge-http">${t.http_status_code}</span>` : ''}
        ${t.tls_version ? `<span class="badge" style="background:rgba(168,85,247,0.12);color:#a855f7">${esc(t.tls_version)}</span>` : ''}
        ${sslBadge}
      </div>

      <div class="tc-metrics">
        <div class="tc-metric-item">
          <div class="tc-metric-label">응답시간</div>
          <div class="tc-metric-value ${respClass}">${resp ? Math.round(resp) + ' ms' : '-'}</div>
        </div>
        <div class="tc-metric-item">
          <div class="tc-metric-label">7일 가용률</div>
          <div class="tc-metric-value ${uptimePct >= 99 ? 'fast' : (uptimePct >= 95 ? 'medium' : 'slow')}">
            ${checks > 0 ? uptimePct.toFixed(1) + '%' : '-'}
          </div>
        </div>
        <div class="tc-metric-item">
          <div class="tc-metric-label">DNS</div>
          <div class="tc-metric-value">${t.dns_lookup_ms ? Math.round(t.dns_lookup_ms) + ' ms' : '-'}</div>
        </div>
        <div class="tc-metric-item">
          <div class="tc-metric-label">TLS 연결</div>
          <div class="tc-metric-value">${t.http_duration_tls_ms ? Math.round(t.http_duration_tls_ms) + ' ms' : '-'}</div>
        </div>
      </div>

      ${renderUptimeBar(t.id)}

      <div class="tc-footer">
        <span>${noData ? '프로브 대기' : fmtTime(t.probe_time)}</span>
        <span style="color:var(--text-muted)">${checks > 0 ? checks + '회 점검' : ''}</span>
      </div>
    </div>
  `
}

function getUptimePct(id) {
  const s = state.historySummary.find(h => h.id === id)
  if (!s || !s.total_checks) return 0
  return (s.up_checks / s.total_checks) * 100
}

function renderUptimeBar(id) {
  const s = state.historySummary.find(h => h.id === id)
  if (!s || !s.total_checks) return '<div class="uptime-bar">' + Array(20).fill('<div class="uptime-seg"></div>').join('') + '</div>'
  const pct = s.up_checks / s.total_checks
  const segs = Array.from({ length: 20 }, (_, i) => {
    const cls = (i / 20) < pct ? 'up' : 'down'
    return `<div class="uptime-seg ${cls}"></div>`
  })
  return `<div class="uptime-bar">${segs.join('')}</div>`
}

// ─── 즉시 프로브 ─────────────────────────────────────────────
async function probeOne(id) {
  if (state.probing.has(id)) return
  state.probing.add(id)

  // 해당 카드만 스피너 표시
  if (state.page === 'dashboard') {
    const cards = document.querySelectorAll('.target-card')
    cards.forEach(el => {
      if (el.getAttribute('onclick')?.includes(`(${id})`)) {
        el.querySelector('.tc-head').insertAdjacentHTML('beforeend', '<div class="spinner" id="spin-' + id + '" style="margin-left:auto"></div>')
      }
    })
  }

  try {
    const res = await api(`/probe/${id}`, { method: 'POST' })
    const st = res.probe_success ? 'UP' : 'DOWN'
    toast(`${esc(res.target_name)}: ${st} | ${Math.round(res.probe_duration_ms || 0)}ms`, res.probe_success ? 'success' : 'error')
    // 대시보드 갱신
    if (state.page === 'dashboard') { await loadAll(); renderDashboard() }
  } catch (err) {
    toast('프로브 오류: ' + err.message, 'error')
  } finally {
    state.probing.delete(id)
  }
}

async function probeAll() {
  toast('전체 프로브 시작…', 'info')
  try {
    const res = await api('/probe-all', { method: 'POST' })
    toast(`완료: ${res.up}UP / ${res.down}DOWN | ${res.elapsed_ms}ms`, res.down > 0 ? 'warn' : 'success')
    if (state.page === 'dashboard') { await loadAll(); renderDashboard() }
  } catch (err) {
    toast('전체 프로브 오류: ' + err.message, 'error')
  }
}

// ──────────────────────────────────────────────────────────────
// 2. 상세 모달 (타겟 클릭)
// ──────────────────────────────────────────────────────────────
async function showDetail(id) {
  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay'
  overlay.id = 'detail-modal'
  overlay.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title" id="modal-title">로드 중…</div>
        <button class="modal-close" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="modal-body" id="modal-body">
        <div class="loading-overlay"><div class="spinner"></div></div>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal() })

  try {
    const [target, chart24h] = await Promise.all([
      api(`/targets`).then(ts => ts.find(t => t.id === id)),
      api(`/history-chart/${id}?hours=24`)
    ])

    const latest = state.status?.targets.find(t => t.id === id) || {}

    document.getElementById('modal-title').textContent = `${target?.name || id} — 상세 현황`
    document.getElementById('modal-body').innerHTML = buildDetailBody(target, latest, chart24h)

    // 차트 렌더링
    renderDetailChart(chart24h)
    renderPhaseBar(latest)

  } catch (err) {
    document.getElementById('modal-body').innerHTML = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation" style="color:var(--red)"></i><p>${err.message}</p></div>`
  }
}

function closeModal() {
  const m = document.getElementById('detail-modal')
  if (m) m.remove()
}

function buildDetailBody(target, latest, chart24h) {
  const isUp = latest.probe_success === 1

  const upCnt  = chart24h.filter(r => r.probe_success === 1).length
  const pct24h = chart24h.length > 0 ? ((upCnt / chart24h.length) * 100).toFixed(1) : '-'

  return `
    <!-- 현재 상태 메트릭 -->
    <div class="detail-metrics">
      ${dMetric('상태', isUp ? '✓ UP' : '✗ DOWN', isUp ? 'green' : 'red', '')}
      ${dMetric('응답시간', latest.probe_duration_ms ? Math.round(latest.probe_duration_ms) + ' ms' : '-', '', '')}
      ${dMetric('HTTP 상태', latest.http_status_code || '-', '', '')}
      ${dMetric('리다이렉트', latest.http_redirects != null ? latest.http_redirects + '회' : '-', '', '')}
      ${dMetric('DNS 조회', latest.dns_lookup_ms ? Math.round(latest.dns_lookup_ms) + ' ms' : '-', 'accent', '')}
      ${dMetric('TLS 연결', latest.http_duration_tls_ms ? Math.round(latest.http_duration_tls_ms) + ' ms' : '-', 'yellow', '')}
      ${dMetric('SSL 만료', latest.ssl_expiry_days != null ? latest.ssl_expiry_days + '일' : '-',
          latest.ssl_expiry_days < 14 ? 'red' : (latest.ssl_expiry_days < 30 ? 'yellow' : 'green'), '')}
      ${dMetric('24h 가용률', pct24h + '%', parseFloat(pct24h) >= 99 ? 'green' : (parseFloat(pct24h) >= 95 ? '' : 'red'), '')}
    </div>

    <!-- TLS 정보 -->
    ${(latest.tls_version || latest.tls_cipher || latest.ssl_earliest_expiry) ? `
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-header"><div class="panel-title"><i class="fa-solid fa-lock"></i> SSL/TLS 정보</div></div>
      <div class="panel-body">
        <div class="detail-metrics">
          ${dMetric('TLS 버전', latest.tls_version || '-', 'green', '')}
          ${dMetric('암호화 스위트', latest.tls_cipher ? latest.tls_cipher.substring(0, 30) : '-', '', '')}
          ${dMetric('인증서 만료일', latest.ssl_earliest_expiry || '-', '', '')}
          ${dMetric('HTTP 버전', latest.http_version || '-', 'accent', '')}
        </div>
      </div>
    </div>
    ` : ''}

    <!-- 응답 단계별 타임라인 -->
    <div id="phase-bar-wrap"></div>

    <!-- 24시간 응답시간 차트 -->
    <div class="panel" style="margin-bottom:14px">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-solid fa-chart-line"></i> 24시간 응답시간</div>
      </div>
      <div class="panel-body no-pad" style="padding:12px">
        <div class="chart-wrap" style="height:160px">
          <canvas id="detail-chart" style="height:160px"></canvas>
        </div>
      </div>
    </div>

    <!-- 최근 프로브 기록 -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-solid fa-table-list"></i> 최근 프로브 기록 (최대 50건)</div>
      </div>
      <div class="panel-body no-pad">
        <div class="history-table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>시간</th><th>상태</th><th>HTTP</th><th>응답(ms)</th>
                <th>DNS(ms)</th><th>TLS(ms)</th><th>처리(ms)</th><th>전송(ms)</th>
                <th>SSL만료</th><th>오류</th>
              </tr>
            </thead>
            <tbody>
              ${chart24h.slice(-50).reverse().map(r => `
                <tr>
                  <td style="white-space:nowrap">${fmtTime(r.probe_time)}</td>
                  <td class="${r.probe_success ? 'status-up' : 'status-down'}">${r.probe_success ? 'UP' : 'DOWN'}</td>
                  <td>${r.http_status_code || '-'}</td>
                  <td>${r.probe_duration_ms ? Math.round(r.probe_duration_ms) : '-'}</td>
                  <td>${r.dns_lookup_ms ? Math.round(r.dns_lookup_ms) : '-'}</td>
                  <td>${r.http_duration_tls_ms ? Math.round(r.http_duration_tls_ms) : '-'}</td>
                  <td>${r.http_duration_processing_ms ? Math.round(r.http_duration_processing_ms) : '-'}</td>
                  <td>${r.http_duration_transfer_ms ? Math.round(r.http_duration_transfer_ms) : '-'}</td>
                  <td>${r.ssl_expiry_days != null ? r.ssl_expiry_days + '일' : '-'}</td>
                  <td style="color:var(--red);font-size:10px">${esc(r.error_msg || '')}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn btn-primary btn-sm" onclick="probeOne(${target?.id});closeModal()">
        <i class="fa-solid fa-bolt"></i> 즉시 프로브
      </button>
      <button class="btn btn-secondary btn-sm" onclick="closeModal()">닫기</button>
    </div>
  `
}

function dMetric(label, value, color, sub) {
  return `
    <div class="detail-metric-card">
      <div class="detail-metric-label">${label}</div>
      <div class="detail-metric-value ${color}">${value}</div>
      ${sub ? `<div class="detail-metric-sub">${sub}</div>` : ''}
    </div>
  `
}

function renderPhaseBar(latest) {
  const wrap = document.getElementById('phase-bar-wrap')
  if (!wrap) return
  const total = latest.probe_duration_ms || 0
  if (!total) return

  const phases = [
    { label: 'DNS',     key: 'dns_lookup_ms',                   cls: 'dns' },
    { label: 'Connect', key: 'http_duration_connect_ms',        cls: 'conn' },
    { label: 'TLS',     key: 'http_duration_tls_ms',            cls: 'tls' },
    { label: '처리',    key: 'http_duration_processing_ms',     cls: 'proc' },
    { label: '전송',    key: 'http_duration_transfer_ms',       cls: 'xfer' }
  ]

  const rows = phases.map(p => {
    const val = latest[p.key]
    if (!val) return ''
    const pct = Math.min((val / total) * 100, 100)
    return `
      <div class="phase-row">
        <span class="phase-label">${p.label}</span>
        <div class="phase-track"><div class="phase-fill ${p.cls}" style="width:${pct.toFixed(1)}%"></div></div>
        <span class="phase-val">${Math.round(val)} ms</span>
      </div>
    `
  }).filter(Boolean).join('')

  if (!rows) return

  wrap.innerHTML = `
    <div class="phase-bar-wrap" style="margin-bottom:14px">
      <div class="phase-bar-title">응답 단계별 분석 (총 ${Math.round(total)} ms)</div>
      ${rows}
    </div>
  `
}

function renderDetailChart(data) {
  const canvas = document.getElementById('detail-chart')
  if (!canvas || !data.length) return

  const labels = data.map(r => fmtTime(r.probe_time))
  const resps  = data.map(r => r.probe_duration_ms ? Math.round(r.probe_duration_ms) : null)
  const colors = data.map(r => r.probe_success ? 'rgba(34,197,94,0.8)' : 'rgba(239,68,68,0.8)')

  new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: '응답시간 (ms)',
        data: resps,
        backgroundColor: colors,
        borderColor: colors,
        borderWidth: 1,
        borderRadius: 2
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => {
              const r = data[ctx.dataIndex]
              return [
                `응답: ${ctx.raw} ms`,
                `상태: ${r.probe_success ? 'UP' : 'DOWN'}`,
                r.http_status_code ? `HTTP: ${r.http_status_code}` : ''
              ].filter(Boolean)
            }
          }
        }
      },
      scales: {
        x: { ticks: { color: '#8a8fa8', maxTicksLimit: 12, font: { size: 10 } }, grid: { color: '#353849' } },
        y: { ticks: { color: '#8a8fa8', font: { size: 10 } }, grid: { color: '#353849' }, beginAtZero: true }
      }
    }
  })
}

// ──────────────────────────────────────────────────────────────
// 3. 수집 이력 (7일)
// ──────────────────────────────────────────────────────────────
let historyChart = null

function renderHistory() {
  if (!state.historySummary) return
  const content = document.getElementById('content')

  // 카테고리 순서: 한화생명(hanwha) → 금융기관 → 은행 → 카드 → 증권 → 보험 → 기타
  const CAT_SORT_ORDER = ['hanwha', 'institution', 'bank', 'card', 'securities', 'insurance', 'other']
  const getCatRank = row => {
    const idx = CAT_SORT_ORDER.indexOf(row.category)
    return idx === -1 ? CAT_SORT_ORDER.length : idx
  }
  const sorted = [...state.historySummary].sort((a, b) => {
    const diff = getCatRank(a) - getCatRank(b)
    if (diff !== 0) return diff
    // 같은 카테고리 내에서는 이름 가나다 순
    return a.name.localeCompare(b.name, 'ko')
  })

  content.innerHTML = `
    <!-- 7일 요약 테이블 -->
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-solid fa-table"></i> 7일 가용성 요약</div>
      </div>
      <div class="panel-body no-pad">
        <div class="history-table-wrap">
          <table class="data-table" id="summary-table">
            <thead>
              <tr>
                <th>대상</th><th>카테고리</th><th>총 점검</th><th>가용률</th>
                <th>평균(ms)</th><th>최소(ms)</th><th>최대(ms)</th>
                <th>평균DNS(ms)</th><th>평균TLS(ms)</th><th>평균처리(ms)</th>
                <th>SSL만료</th>
              </tr>
            </thead>
            <tbody>
              ${sorted.map(row => {
                const pct = row.total_checks > 0
                  ? ((row.up_checks / row.total_checks) * 100).toFixed(2)
                  : null
                const pctClass = pct === null ? 'status-nodata' : (pct >= 99 ? 'pct-high' : (pct >= 95 ? 'pct-medium' : 'pct-low'))
                const catMeta = CAT_META[row.category] || CAT_META.other
                return `
                  <tr>
                    <td><b>${esc(row.name)}</b></td>
                    <td><span style="color:${catMeta.color}"><i class="${catMeta.icon}"></i> ${catMeta.label}</span></td>
                    <td>${row.total_checks}</td>
                    <td class="${pctClass}">${pct !== null ? pct + '%' : '-'}</td>
                    <td>${row.avg_response_ms ?? '-'}</td>
                    <td>${row.min_response_ms ?? '-'}</td>
                    <td>${row.max_response_ms ?? '-'}</td>
                    <td>${row.avg_dns_ms ?? '-'}</td>
                    <td>${row.avg_tls_ms ?? '-'}</td>
                    <td>${row.avg_processing_ms ?? '-'}</td>
                    <td class="${row.ssl_expiry_days < 14 ? 'pct-low' : (row.ssl_expiry_days < 30 ? 'pct-medium' : '')}">${row.ssl_expiry_days != null ? row.ssl_expiry_days + '일' : '-'}</td>
                  </tr>
                `
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- 개별 대상 상세 이력 -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-solid fa-chart-line"></i> 대상별 24시간 응답 차트</div>
        <select class="form-control" id="history-target-sel" style="width:200px"
                onchange="loadHistoryChart(this.value)">
          <option value="">대상 선택</option>
          ${sorted.map(r =>
            `<option value="${r.id}">${esc(r.name)}</option>`
          ).join('')}
        </select>
      </div>
      <div class="panel-body no-pad" style="padding:16px">
        <div class="chart-wrap" style="height:200px">
          <canvas id="history-chart-canvas" style="height:200px"></canvas>
        </div>
      </div>
    </div>
  `
}

async function loadHistoryChart(id) {
  if (!id) return
  try {
    const data = await api(`/history-chart/${id}?hours=24`)
    const canvas = document.getElementById('history-chart-canvas')
    if (!canvas) return

    if (historyChart) { historyChart.destroy(); historyChart = null }

    const labels = data.map(r => fmtTime(r.probe_time))
    const resps  = data.map(r => r.probe_duration_ms ? Math.round(r.probe_duration_ms) : null)
    const bgColors = data.map(r => r.probe_success ? 'rgba(34,197,94,0.7)' : 'rgba(239,68,68,0.7)')

    historyChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: '응답시간 (ms)',
          data: resps, backgroundColor: bgColors, borderColor: bgColors, borderWidth: 1, borderRadius: 2
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8a8fa8', maxTicksLimit: 15, font: { size: 10 } }, grid: { color: '#353849' } },
          y: { ticks: { color: '#8a8fa8', font: { size: 10 } }, grid: { color: '#353849' }, beginAtZero: true }
        }
      }
    })
  } catch (err) { toast('차트 로드 오류: ' + err.message, 'error') }
}

// ──────────────────────────────────────────────────────────────
// 4. 대상 관리
// ──────────────────────────────────────────────────────────────
function renderTargets() {
  // CAT_ORDER 고정 순서 사용 (all 제외)
  const cats = CAT_ORDER.filter(k => k !== 'all').map(k => [k, CAT_META[k]])
  const content = document.getElementById('content')

  // 카테고리별 그룹
  const grouped = {}
  for (const t of state.targets) {
    const k = t.category || 'other'
    if (!grouped[k]) grouped[k] = []
    grouped[k].push(t)
  }

  content.innerHTML = `
    <div style="display:flex;gap:10px;justify-content:flex-end;margin-bottom:16px">
      <button class="btn btn-secondary btn-sm" onclick="openBulkAddModal()">
        <i class="fa-solid fa-list-plus"></i> 국내 금융사 일괄 등록
      </button>
      <button class="btn btn-primary btn-sm" onclick="openTargetModal()">
        <i class="fa-solid fa-plus"></i> 대상 추가
      </button>
    </div>

    ${cats.map(([cat, meta]) => {
      const rows = grouped[cat] || []
      return `
        <div class="panel" style="margin-bottom:14px">
          <div class="panel-header">
            <div class="panel-title" style="color:${meta.color}">
              <i class="${meta.icon}"></i> ${meta.label}
              <span style="font-size:11px;color:var(--text-muted);font-weight:400;margin-left:6px">${rows.length}개</span>
            </div>
          </div>
          <div class="panel-body no-pad" style="padding:12px">
            ${rows.length === 0 ? `<div style="color:var(--text-muted);font-size:12px;text-align:center;padding:12px">등록된 대상 없음</div>` :
              `<div class="target-manage-grid">
                ${rows.map(t => `
                  <div class="manage-card">
                    <div class="manage-card-head">
                      <div class="manage-card-name">${esc(t.name)}</div>
                      <label class="toggle-switch" title="${t.enabled ? '활성' : '비활성'}">
                        <input type="checkbox" ${t.enabled ? 'checked' : ''}
                               onchange="toggleTarget(${t.id}, this.checked)">
                        <span class="toggle-track"></span>
                      </label>
                    </div>
                    <div class="manage-card-url">${esc(t.url)}</div>
                    <div style="font-size:10px;color:var(--text-muted)">${esc(t.sub_category || '')} | ${t.interval_sec}초마다</div>
                    <div class="manage-card-actions">
                      <button class="btn btn-xs btn-secondary" onclick="openTargetModal(${t.id})">
                        <i class="fa-solid fa-pen"></i> 수정
                      </button>
                      <button class="btn btn-xs btn-danger" onclick="deleteTarget(${t.id}, '${esc(t.name)}')">
                        <i class="fa-solid fa-trash"></i>
                      </button>
                    </div>
                  </div>
                `).join('')}
              </div>`
            }
          </div>
        </div>
      `
    }).join('')}
  `
}

async function toggleTarget(id, enabled) {
  const t = state.targets.find(x => x.id === id)
  if (!t) return
  try {
    await api(`/targets/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ ...t, enabled: enabled ? 1 : 0 })
    })
    await fetchTargets(); renderTargets()
    toast(`${esc(t.name)} ${enabled ? '활성화' : '비활성화'} 완료`, 'success')
  } catch (err) { toast(err.message, 'error') }
}

async function deleteTarget(id, name) {
  if (!confirm(`"${name}" 을 삭제하시겠습니까?\n수집된 이력도 함께 삭제됩니다.`)) return
  try {
    await api(`/targets/${id}`, { method: 'DELETE' })
    await fetchTargets(); renderTargets()
    toast(`${esc(name)} 삭제 완료`, 'success')
  } catch (err) { toast(err.message, 'error') }
}

// ─── 대상 추가/수정 모달 ─────────────────────────────────────
function openTargetModal(id) {
  const t = id ? state.targets.find(x => x.id === id) : null
  const title = t ? '대상 수정' : '대상 추가'
  // CAT_ORDER 순서로 select 옵션 생성 (all 제외)
  const cats = CAT_ORDER.filter(k => k !== 'all').map(k => [k, CAT_META[k]])

  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay'
  overlay.id = 'target-modal'
  overlay.innerHTML = `
    <div class="modal" style="max-width:500px">
      <div class="modal-header">
        <div class="modal-title">${title}</div>
        <button class="modal-close" onclick="closeModal2('target-modal')"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="modal-body">
        <form onsubmit="saveTarget(event, ${id || ''})">
          <div class="form-group">
            <label class="form-label">기관명 *</label>
            <input class="form-control" id="t-name" value="${esc(t?.name || '')}" placeholder="예: 한화생명" required>
          </div>
          <div class="form-group">
            <label class="form-label">URL *</label>
            <input class="form-control" id="t-url" value="${esc(t?.url || '')}" placeholder="https://example.com" required>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">카테고리 *</label>
              <select class="form-control" id="t-cat">
                ${cats.map(([k, v]) => `<option value="${k}" ${t?.category === k ? 'selected' : ''}>${v.label}</option>`).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">세부 분류</label>
              <input class="form-control" id="t-subcat" value="${esc(t?.sub_category || '')}" placeholder="예: 생명보험">
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">점검 주기 (초)</label>
            <input class="form-control" type="number" id="t-interval" value="${t?.interval_sec || 60}" min="30" max="3600">
          </div>
          <div style="display:flex;gap:8px;margin-top:16px">
            <button type="submit" class="btn btn-primary">저장</button>
            <button type="button" class="btn btn-secondary" onclick="closeModal2('target-modal')">취소</button>
          </div>
        </form>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
}

async function saveTarget(e, id) {
  e.preventDefault()
  const body = {
    name:         document.getElementById('t-name').value.trim(),
    url:          document.getElementById('t-url').value.trim(),
    category:     document.getElementById('t-cat').value,
    sub_category: document.getElementById('t-subcat').value.trim() || null,
    interval_sec: parseInt(document.getElementById('t-interval').value) || 60,
    enabled: 1
  }
  try {
    if (id) await api(`/targets/${id}`, { method: 'PUT', body: JSON.stringify(body) })
    else     await api('/targets', { method: 'POST', body: JSON.stringify(body) })
    closeModal2('target-modal')
    await fetchTargets(); renderTargets()
    toast(`${esc(body.name)} ${id ? '수정' : '추가'} 완료`, 'success')
  } catch (err) { toast(err.message, 'error') }
}

// ─── 국내 금융사 일괄 등록 모달 ─────────────────────────────
const FINANCE_PRESETS = {
  hanwha: [
    { name: '한화생명 홈페이지',      url: 'https://www.hanwhalife.com',                       sub: '대표사이트' },
    { name: '한화생명 고객센터',      url: 'https://www.hanwhalife.com/customer/center.do',    sub: '고객센터' },
    { name: '한화생명 모바일',        url: 'https://m.hanwhalife.com',                         sub: '모바일웹' },
    { name: '한화생명 인터넷서비스',  url: 'https://direct.hanwhalife.com',                    sub: '인터넷서비스' },
    { name: '한화생명 금융몰',        url: 'https://mall.hanwhalife.com',                      sub: '금융몰' },
    { name: '한화손해보험',           url: 'https://www.hwgic.com',                            sub: '손해보험' },
    { name: '한화투자증권',           url: 'https://www.hanwhawm.com',                         sub: '증권' },
    { name: '한화자산운용',           url: 'https://www.hanwhafund.co.kr',                     sub: '자산운용' }
  ],
  institution: [
    { name: '한국은행',     url: 'https://www.bok.or.kr',        sub: '중앙은행' },
    { name: '금융감독원',   url: 'https://www.fss.or.kr',        sub: '감독기관' },
    { name: '금융위원회',   url: 'https://www.fsc.go.kr',        sub: '감독기관' },
    { name: '금융결제원',   url: 'https://www.kftc.or.kr',       sub: '결제인프라' },
    { name: '예금보험공사', url: 'https://www.kdic.or.kr',       sub: '보험기관' },
    { name: '한국거래소',   url: 'https://www.krx.co.kr',        sub: '증권거래소' },
    { name: '신용보증기금', url: 'https://www.kodit.co.kr',      sub: '보증기관' },
    { name: '기술보증기금', url: 'https://www.kibo.or.kr',       sub: '보증기관' }
  ],
  bank: [
    { name: 'KB국민은행',   url: 'https://www.kbstar.com',       sub: '시중은행' },
    { name: '신한은행',     url: 'https://www.shinhan.com',      sub: '시중은행' },
    { name: '우리은행',     url: 'https://www.wooribank.com',    sub: '시중은행' },
    { name: '하나은행',     url: 'https://www.kebhana.com',      sub: '시중은행' },
    { name: 'NH농협은행',   url: 'https://banking.nonghyup.com', sub: '특수은행' },
    { name: 'IBK기업은행',  url: 'https://www.ibk.co.kr',        sub: '특수은행' },
    { name: '산업은행',     url: 'https://www.kdb.co.kr',        sub: '특수은행' },
    { name: '카카오뱅크',   url: 'https://www.kakaobank.com',    sub: '인터넷은행' },
    { name: '케이뱅크',     url: 'https://www.kbanknow.com',     sub: '인터넷은행' },
    { name: '토스뱅크',     url: 'https://www.tossbank.com',     sub: '인터넷은행' }
  ],
  card: [
    { name: '신한카드',     url: 'https://www.shinhancard.com',  sub: '카드사' },
    { name: '삼성카드',     url: 'https://www.samsungcard.com',  sub: '카드사' },
    { name: '현대카드',     url: 'https://www.hyundaicard.com',  sub: '카드사' },
    { name: 'KB국민카드',   url: 'https://card.kbcard.com',      sub: '카드사' },
    { name: '롯데카드',     url: 'https://www.lottecard.co.kr',  sub: '카드사' },
    { name: '우리카드',     url: 'https://pc.wooricard.com',     sub: '카드사' },
    { name: '하나카드',     url: 'https://www.hanacard.co.kr',   sub: '카드사' },
    { name: 'BC카드',       url: 'https://www.bccard.com',       sub: '카드사' }
  ],
  insurance: [
    { name: '한화생명',     url: 'https://www.hanwhalife.com',   sub: '생명보험' },
    { name: '삼성생명',     url: 'https://www.samsunglife.com',  sub: '생명보험' },
    { name: '교보생명',     url: 'https://www.kyobo.co.kr',      sub: '생명보험' },
    { name: 'NH농협생명',   url: 'https://www.nhlife.co.kr',     sub: '생명보험' },
    { name: '삼성화재',     url: 'https://www.samsungfire.com',  sub: '손해보험' },
    { name: 'DB손해보험',   url: 'https://www.idbins.com',       sub: '손해보험' },
    { name: '현대해상',     url: 'https://www.hi.co.kr',         sub: '손해보험' },
    { name: 'KB손해보험',   url: 'https://www.kbinsure.co.kr',   sub: '손해보험' },
    { name: '메리츠화재',   url: 'https://www.meritzfire.com',   sub: '손해보험' },
    { name: '롯데손해보험', url: 'https://www.lotteins.co.kr',   sub: '손해보험' }
  ],
  securities: [
    { name: 'NH투자증권',   url: 'https://www.nhqv.com',         sub: '종합증권' },
    { name: '미래에셋증권', url: 'https://securities.miraeasset.com', sub: '종합증권' },
    { name: '삼성증권',     url: 'https://www.samsungsecurities.com', sub: '종합증권' },
    { name: 'KB증권',       url: 'https://www.kbsec.com',         sub: '종합증권' },
    { name: '키움증권',     url: 'https://www.kiwoom.com',        sub: '온라인증권' },
    { name: '한국투자증권', url: 'https://www.truefriend.com',    sub: '종합증권' },
    { name: '신한투자증권', url: 'https://www.shinhansec.com',    sub: '종합증권' },
    { name: '카카오페이증권', url: 'https://securities.kakaopay.com', sub: '온라인증권' }
  ]
}

function openBulkAddModal() {
  const existingUrls = new Set(state.targets.map(t => t.url))
  // CAT_ORDER 순서로 섹션 표시 (FINANCE_PRESETS 에 있는 카테고리만)
  const sections = CAT_ORDER.filter(cat => FINANCE_PRESETS[cat]).map(cat => {
    const items = FINANCE_PRESETS[cat]
    const meta = CAT_META[cat]
    const rows = items.map(item => {
      const alreadyAdded = existingUrls.has(item.url)
      return `
        <label class="form-check" style="padding:4px 0">
          <input type="checkbox" class="bulk-chk" data-cat="${cat}"
                 data-name="${esc(item.name)}" data-url="${esc(item.url)}" data-sub="${esc(item.sub)}"
                 ${alreadyAdded ? 'disabled checked' : 'checked'}>
          <span class="form-check-label" style="${alreadyAdded ? 'color:var(--text-muted)' : ''}">
            ${esc(item.name)}
            <span style="color:var(--text-muted);font-size:10px"> — ${esc(item.url)}</span>
            ${alreadyAdded ? '<span style="color:var(--green);font-size:10px"> ✓ 등록됨</span>' : ''}
          </span>
        </label>
      `
    }).join('')
    return `
      <div style="margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;color:${meta.color};margin-bottom:8px;display:flex;align-items:center;gap:6px">
          <i class="${meta.icon}"></i> ${meta.label}
        </div>
        ${rows}
      </div>
    `
  }).join('')

  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay'
  overlay.id = 'bulk-modal'
  overlay.innerHTML = `
    <div class="modal" style="max-width:620px">
      <div class="modal-header">
        <div class="modal-title">국내 금융사 일괄 등록</div>
        <button class="modal-close" onclick="closeModal2('bulk-modal')"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="modal-body">
        <div style="display:flex;gap:8px;margin-bottom:12px">
          <button class="btn btn-secondary btn-xs" onclick="bulkCheckAll(true)">전체 선택</button>
          <button class="btn btn-secondary btn-xs" onclick="bulkCheckAll(false)">전체 해제</button>
        </div>
        ${sections}
        <div style="margin-top:16px;display:flex;gap:8px">
          <button class="btn btn-primary" onclick="executeBulkAdd()">
            <i class="fa-solid fa-download"></i> 선택 항목 등록
          </button>
          <button class="btn btn-secondary" onclick="closeModal2('bulk-modal')">취소</button>
        </div>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
}

function bulkCheckAll(checked) {
  document.querySelectorAll('.bulk-chk:not(:disabled)').forEach(el => el.checked = checked)
}

async function executeBulkAdd() {
  const items = [...document.querySelectorAll('.bulk-chk:checked:not(:disabled)')]
  if (!items.length) { toast('선택된 항목 없음', 'warn'); return }

  let ok = 0, fail = 0
  for (const el of items) {
    try {
      await api('/targets', {
        method: 'POST',
        body: JSON.stringify({
          name: el.dataset.name,
          url:  el.dataset.url,
          category: el.dataset.cat,
          sub_category: el.dataset.sub,
          interval_sec: 60
        })
      })
      ok++
    } catch { fail++ }
  }

  closeModal2('bulk-modal')
  await fetchTargets(); renderTargets()
  toast(`등록 완료: ${ok}개 성공${fail > 0 ? `, ${fail}개 실패(중복)` : ''}`, 'success')
}

function closeModal2(id) {
  const el = document.getElementById(id)
  if (el) el.remove()
}

// ──────────────────────────────────────────────────────────────
// 5. 알림 설정
// ──────────────────────────────────────────────────────────────
function renderAlertConf() {
  const content = document.getElementById('content')
  content.innerHTML = `
    <div class="panel" style="max-width:700px;margin-bottom:16px">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-solid fa-bell"></i> 알림 설정</div>
        <button class="btn btn-primary btn-sm" onclick="openAlertModal()">
          <i class="fa-solid fa-plus"></i> 추가
        </button>
      </div>
      <div class="panel-body">
        ${state.alerts.length === 0 ? `
          <div class="empty-state" style="padding:30px">
            <i class="fa-solid fa-bell-slash"></i>
            <h3>알림 설정 없음</h3>
            <p>장애·응답지연·SSL만료 발생 시 Gmail로 자동 발송됩니다.<br>추가 버튼으로 이메일 알림을 설정하세요.</p>
          </div>
        ` : state.alerts.map(a => `
          <div class="alert-config-card">
            <div class="alert-config-head">
              <div class="alert-config-name">${esc(a.name)}</div>
              <span class="badge ${a.enabled ? 'badge-up' : 'badge-nodata'}">${a.enabled ? '활성' : '비활성'}</span>
            </div>
            <div style="font-size:12px;color:var(--text-secondary);margin-bottom:10px">
              <i class="fa-solid fa-envelope"></i> ${esc(a.to_email)}
            </div>
            <div style="display:flex;gap:16px;font-size:12px;color:var(--text-muted)">
              <span><i class="fa-solid fa-circle-xmark"></i> 장애: ${a.down_notify ? 'ON' : 'OFF'}</span>
              <span><i class="fa-solid fa-gauge"></i> 임계값: ${a.threshold_ms}ms</span>
              <span><i class="fa-solid fa-lock"></i> SSL경고: ${a.ssl_warn_days}일</span>
            </div>
            <div style="display:flex;gap:8px;margin-top:10px">
              <button class="btn btn-xs btn-secondary" onclick="openAlertModal(${a.id})">수정</button>
              <button class="btn btn-xs btn-danger" onclick="deleteAlert(${a.id})">삭제</button>
              <button class="btn btn-xs btn-success" onclick="testAlert(${a.id})">
                <i class="fa-solid fa-paper-plane"></i> 테스트 발송
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Gmail SMTP 안내 -->
    <div class="panel" style="max-width:700px">
      <div class="panel-header">
        <div class="panel-title"><i class="fa-brands fa-google"></i> Gmail SMTP 설정 안내</div>
      </div>
      <div class="panel-body">
        <div style="font-size:13px;line-height:1.8;color:var(--text-secondary)">
          <p style="margin-bottom:8px"><b style="color:var(--text-primary)">1. Gmail 앱 비밀번호 발급</b></p>
          <p>Google 계정 → 보안 → 2단계 인증 활성화 → 앱 비밀번호 생성</p>
          <p style="margin-bottom:8px;margin-top:10px"><b style="color:var(--text-primary)">2. .env 파일 설정</b></p>
          <pre style="background:var(--bg-input);padding:10px;border-radius:5px;font-size:12px;color:var(--green)">SMTP_USER=your-email@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx  # 앱 비밀번호
SMTP_FROM=FinMonitor &lt;your-email@gmail.com&gt;</pre>
          <p style="margin-top:10px;color:var(--text-muted);font-size:12px">
            * .env 파일을 webapp/ 디렉토리에 생성 후 서버 재시작이 필요합니다.
          </p>
        </div>
      </div>
    </div>
  `
}

function openAlertModal(id) {
  const a = id ? state.alerts.find(x => x.id === id) : null
  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay'
  overlay.id = 'alert-modal'
  overlay.innerHTML = `
    <div class="modal" style="max-width:480px">
      <div class="modal-header">
        <div class="modal-title">${a ? '알림 수정' : '알림 추가'}</div>
        <button class="modal-close" onclick="closeModal2('alert-modal')"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="modal-body">
        <form onsubmit="saveAlert(event, ${id || ''})">
          <div class="form-group">
            <label class="form-label">알림 이름 *</label>
            <input class="form-control" id="a-name" value="${esc(a?.name || 'SOC 알림')}" required>
          </div>
          <div class="form-group">
            <label class="form-label">수신 이메일 *</label>
            <input class="form-control" id="a-email" type="email" value="${esc(a?.to_email || '')}" placeholder="soc@example.com" required>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">응답 임계값 (ms)</label>
              <input class="form-control" type="number" id="a-threshold" value="${a?.threshold_ms ?? 3000}" min="0">
            </div>
            <div class="form-group">
              <label class="form-label">SSL 경고 (일)</label>
              <input class="form-control" type="number" id="a-ssl" value="${a?.ssl_warn_days ?? 30}" min="0">
            </div>
          </div>
          <div class="form-group">
            <label class="form-check">
              <input type="checkbox" id="a-down" ${(!a || a.down_notify) ? 'checked' : ''}>
              <span class="form-check-label">장애(DOWN) 알림 활성화</span>
            </label>
          </div>
          <div class="form-group">
            <label class="form-check">
              <input type="checkbox" id="a-enabled" ${(!a || a.enabled) ? 'checked' : ''}>
              <span class="form-check-label">알림 활성화</span>
            </label>
          </div>
          <div style="display:flex;gap:8px;margin-top:16px">
            <button type="submit" class="btn btn-primary">저장</button>
            <button type="button" class="btn btn-secondary" onclick="closeModal2('alert-modal')">취소</button>
          </div>
        </form>
      </div>
    </div>
  `
  document.body.appendChild(overlay)
}

async function saveAlert(e, id) {
  e.preventDefault()
  const body = {
    name:         document.getElementById('a-name').value.trim(),
    to_email:     document.getElementById('a-email').value.trim(),
    threshold_ms: parseInt(document.getElementById('a-threshold').value) || 3000,
    ssl_warn_days:parseInt(document.getElementById('a-ssl').value) || 30,
    down_notify:  document.getElementById('a-down').checked ? 1 : 0,
    enabled:      document.getElementById('a-enabled').checked ? 1 : 0
  }
  try {
    if (id) await api(`/alerts/${id}`, { method: 'PUT', body: JSON.stringify(body) })
    else     await api('/alerts', { method: 'POST', body: JSON.stringify(body) })
    closeModal2('alert-modal')
    await fetchAlerts(); renderAlertConf()
    toast(`알림 설정 ${id ? '수정' : '추가'} 완료`, 'success')
  } catch (err) { toast(err.message, 'error') }
}

async function deleteAlert(id) {
  if (!confirm('알림 설정을 삭제하시겠습니까?')) return
  try {
    await api(`/alerts/${id}`, { method: 'DELETE' })
    await fetchAlerts(); renderAlertConf()
    toast('알림 삭제 완료', 'success')
  } catch (err) { toast(err.message, 'error') }
}

async function testAlert(id) {
  toast('테스트 메일 발송 중…', 'info')
  try {
    const res = await api(`/alerts/${id}/test`, { method: 'POST' })
    toast(res.message || '테스트 메일 발송 완료', 'success')
  } catch (err) { toast('발송 실패: ' + err.message + ' (SMTP 설정을 확인하세요)', 'warn') }
}

// ──────────────────────────────────────────────────────────────
// 6. 알림 이력
// ──────────────────────────────────────────────────────────────
async function renderAlertLog() {
  const content = document.getElementById('content')
  try {
    const data = await api('/alert-history')
    const typeLabel = { down: '장애', recovery: '복구', slow: '응답지연', ssl_expiry: 'SSL만료' }
    const typeBadge = { down: 'badge-down', recovery: 'badge-up', slow: 'badge-ssl-warn', ssl_expiry: 'badge-ssl-crit' }

    content.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title"><i class="fa-solid fa-inbox"></i> 알림 발송 이력 (최근 200건)</div>
        </div>
        <div class="panel-body no-pad">
          ${data.length === 0 ? `<div class="empty-state" style="padding:40px"><i class="fa-solid fa-inbox"></i><h3>알림 이력 없음</h3></div>` : `
            <div class="history-table-wrap">
              <table class="data-table">
                <thead>
                  <tr><th>발송시간</th><th>유형</th><th>대상</th><th>알림설정</th><th>메시지</th><th>발송결과</th></tr>
                </thead>
                <tbody>
                  ${data.map(r => `
                    <tr>
                      <td style="white-space:nowrap">${fmtTime(r.sent_at)}</td>
                      <td><span class="badge ${typeBadge[r.alert_type] || 'badge-nodata'}">${typeLabel[r.alert_type] || r.alert_type}</span></td>
                      <td>${esc(r.target_name || '-')}</td>
                      <td>${esc(r.alert_name || '-')}</td>
                      <td style="font-size:11px">${esc(r.message || '')}</td>
                      <td class="${r.success ? 'status-up' : 'status-down'}">${r.success ? '✓ 성공' : '✗ 실패'}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          `}
        </div>
      </div>
    `
  } catch (err) {
    content.innerHTML = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation"></i><p>${err.message}</p></div>`
  }
}

// ══════════════════════════════════════════════════════════════
//  모듈 B : 블랙박스 공격 대시보드 (프론트 틀 — 세부 개발 예정)
// ══════════════════════════════════════════════════════════════

// ── 심각도 배지 헬퍼 ─────────────────────────────────────────
function severityBadge(sev) {
  const map = {
    critical: { label: 'Critical', cls: 'sev-critical' },
    high:     { label: 'High',     cls: 'sev-high'     },
    medium:   { label: 'Medium',   cls: 'sev-medium'   },
    low:      { label: 'Low',      cls: 'sev-low'      },
    info:     { label: 'Info',     cls: 'sev-info'     },
  }
  const s = map[sev] || { label: sev || '-', cls: 'sev-info' }
  return `<span class="sev-badge ${s.cls}">${s.label}</span>`
}

function eventTypeBadge(type) {
  const map = {
    scan:        { icon: 'fa-magnifying-glass', color: '#3b82f6' },
    exploit:     { icon: 'fa-bug',              color: '#ef4444' },
    ddos:        { icon: 'fa-wave-square',      color: '#f97316' },
    brute_force: { icon: 'fa-key',              color: '#a855f7' },
    anomaly:     { icon: 'fa-circle-exclamation', color: '#f59e0b' },
    other:       { icon: 'fa-circle-dot',       color: '#8a8fa8' },
  }
  const m = map[type] || map.other
  return `<span style="color:${m.color}"><i class="fa-solid ${m.icon}"></i> ${type || '-'}</span>`
}

// ────────────────────────────────────────────────────────────
//  B-1. 실시간 대시보드
// ────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════
//  모듈 C : ASM 블랙박스 공격 대시보드 (완전 구현)
// ════════════════════════════════════════════════════════════════

// ── C-0. 공통 헬퍼 ──────────────────────────────────────────────

function sevBadge(sev) {
  const cls = { critical:'sev-critical', high:'sev-high', medium:'sev-medium',
                low:'sev-low', info:'sev-info' }
  const lbl = { critical:'CRITICAL', high:'HIGH', medium:'MEDIUM', low:'LOW', info:'INFO' }
  return `<span class="sev-badge ${cls[sev]||'sev-info'}">${lbl[sev]||String(sev||'').toUpperCase()}</span>`
}

function riskBar(score) {
  const s = Math.max(0, Math.min(100, score || 0))
  const col = s >= 70 ? '#ef4444' : s >= 40 ? '#f59e0b' : '#22c55e'
  return `<div class="risk-bar-wrap" title="${s}점">
    <div class="risk-bar-fill" style="width:${s}%;background:${col}"></div>
    <span class="risk-bar-label">${s}</span>
  </div>`
}

function portPill(ports) {
  if (!ports || !ports.length) return '<span class="muted">-</span>'
  const HIGHLIGHT = [80,443,22,3306,3389,8080,8443,445,21,25]
  return ports.slice(0, 12).map(p => {
    const hl = HIGHLIGHT.includes(p)
    return `<span class="port-pill${hl?' port-pill-hl':''}">${p}</span>`
  }).join('') + (ports.length > 12 ? `<span class="muted" style="font-size:10px">+${ports.length-12}</span>` : '')
}

function fqdnCell(fqdns) {
  if (!fqdns || !fqdns.length) return '<span class="muted">-</span>'
  const shown = fqdns.slice(0, 4)
  const rest  = fqdns.length - 4
  return `<div class="fqdn-cell">${
    shown.map(f => `<span class="fqdn-chip" title="${esc(f)}">${esc(f)}</span>`).join('')
  }${rest > 0 ? `<span class="fqdn-more">+${rest}개</span>` : ''}</div>`
}

function techChips(techs) {
  if (!techs || !techs.length) return '<span class="muted">-</span>'
  return techs.slice(0, 6).map(t => `<span class="tech-chip">${esc(t)}</span>`).join('')
    + (techs.length > 6 ? `<span class="muted" style="font-size:10px">+${techs.length-6}</span>` : '')
}

function statusPill(st) {
  const m = { active:'pill-green', inactive:'pill-gray', archived:'pill-gray',
              open:'pill-red', acknowledged:'pill-yellow', fixed:'pill-green',
              false_positive:'pill-gray' }
  const l = { active:'활성', inactive:'비활성', archived:'보관',
              open:'OPEN', acknowledged:'검토중', fixed:'해결됨', false_positive:'오탐' }
  return `<span class="status-pill ${m[st]||'pill-gray'}">${l[st]||st}</span>`
}

function asmStatCard(icon, label, value, color, sub) {
  return `
    <div class="asm-stat-card" style="border-top:3px solid ${color}">
      <div class="asm-stat-icon" style="background:${color}22;color:${color}">
        <i class="fa-solid ${icon}"></i>
      </div>
      <div class="asm-stat-body">
        <div class="asm-stat-value">${value}</div>
        <div class="asm-stat-label">${label}</div>
        ${sub ? `<div class="asm-stat-sub">${sub}</div>` : ''}
      </div>
    </div>`
}

function pager(page, limit, total, callbackFn) {
  const pages = Math.ceil(total / limit)
  if (pages <= 1) return ''
  const prev = page > 1      ? `<button class="pager-btn" onclick="${callbackFn}(${page-1})" title="이전">‹</button>` : `<button class="pager-btn" disabled>‹</button>`
  const next = page < pages  ? `<button class="pager-btn" onclick="${callbackFn}(${page+1})" title="다음">›</button>` : `<button class="pager-btn" disabled>›</button>`
  const start = Math.max(1, page-2), end = Math.min(pages, page+2)
  let nums = ''
  for (let p = start; p <= end; p++) {
    nums += `<button class="pager-btn${p===page?' active':''}" onclick="${callbackFn}(${p})">${p}</button>`
  }
  return `<div class="pager">${prev}${nums}${next}<span class="pager-info">${total}건 / ${pages}페이지</span></div>`
}

// ── C-1. 요약 대시보드 ─────────────────────────────────────────
function renderAttackDashboard() {
  const content = document.getElementById('content')
  const s = state.attackSummary || {}
  const sum = s.summary || {}

  const bySev = {}
  ;(s.vuln_by_severity || []).forEach(r => { bySev[r.severity] = r.cnt })

  const totalVulnOpen = (bySev.critical||0) + (bySev.high||0) + (bySev.medium||0) + (bySev.low||0) + (bySev.info||0)

  // 오픈 포트 TOP 10 바
  const maxPortCnt = Math.max(1, ...(s.top_ports||[]).map(r=>r.cnt))
  const topPortHtml = (s.top_ports||[]).map(r => `
    <div class="port-bar-row">
      <span class="port-bar-label">${r.port}</span>
      <div class="port-bar-wrap">
        <div class="port-bar-fill" style="width:${Math.round(r.cnt/maxPortCnt*100)}%"></div>
      </div>
      <span class="port-bar-cnt">${r.cnt}</span>
    </div>`).join('') || `<div class="muted" style="padding:12px 0">데이터 없음</div>`

  // 위험도 상위 자산
  const topRiskHtml = (s.top_risk_assets||[]).slice(0,8).map(r => `
    <tr>
      <td><code style="font-size:11px">${esc(r.ip)}</code></td>
      <td>${fqdnCell(r.fqdns)}</td>
      <td>${riskBar(r.risk_score)}</td>
      <td>
        ${r.vuln_critical > 0 ? `<span class="sev-badge sev-critical">${r.vuln_critical}</span>` : ''}
        ${r.vuln_high > 0     ? `<span class="sev-badge sev-high">${r.vuln_high}</span>` : ''}
        ${r.vuln_medium > 0   ? `<span class="sev-badge sev-medium">${r.vuln_medium}</span>` : ''}
      </td>
      <td>${portPill(r.open_ports)}</td>
      <td><span class="status-pill ${r.is_exposed?'pill-red':'pill-gray'}">${r.is_exposed?'외부노출':'내부'}</span></td>
    </tr>`).join('') || `<tr><td colspan="6" class="text-center muted">데이터 없음</td></tr>`

  // 최근 변경이력
  const changeIcons = {
    new_asset:'fa-plus-circle', new_port:'fa-door-open', port_closed:'fa-door-closed',
    version_change:'fa-arrow-up-right-dots', new_vuln:'fa-bug', vuln_fixed:'fa-shield-check',
    new_fqdn:'fa-globe'
  }
  const changeSevCol = { critical:'#ef4444', high:'#f59e0b', medium:'#a855f7', low:'#22c55e', info:'#8a8fa8' }
  const changeHtml = (s.recent_changes||[]).slice(0,8).map(r => `
    <tr>
      <td style="color:${changeSevCol[r.severity]||'#8a8fa8'}">
        <i class="fa-solid ${changeIcons[r.change_type]||'fa-circle-dot'}"></i>
        <span style="margin-left:4px;font-size:11px">${esc(r.change_type.replace(/_/g,' '))}</span>
      </td>
      <td><code style="font-size:11px">${esc(r.asset_ip||'-')}</code></td>
      <td class="muted" style="font-size:11px">${esc(r.detail&&r.detail.msg ? r.detail.msg : JSON.stringify(r.detail).slice(0,60))}</td>
      <td>${fmtTime(r.detected_at)}</td>
    </tr>`).join('') || `<tr><td colspan="4" class="text-center muted">변경이력 없음</td></tr>`

  content.innerHTML = `
    <!-- 요약 카드 -->
    <div class="asm-stat-row">
      ${asmStatCard('fa-network-wired',  '전체 자산',         sum.total_assets     ?? '-', '#5b70f5')}
      ${asmStatCard('fa-globe',          '외부 노출 IP',       sum.exposed_ips      ?? '-', '#3b82f6', sum.exposed_fqdns!=null?`FQDN ${sum.exposed_fqdns}개`:'')}
      ${asmStatCard('fa-ethernet',       '포트 보유 자산',     sum.assets_with_ports?? '-', '#22c55e')}
      ${asmStatCard('fa-window-maximize','웹 서비스 자산',     sum.assets_with_web  ?? '-', '#a855f7')}
      ${asmStatCard('fa-skull-crossbones','Critical 취약점', sum.vuln_critical     ?? '-', '#ef4444', sum.vuln_high!=null?`High ${sum.vuln_high}개`:'')}
      ${asmStatCard('fa-magnifying-glass-plus','신규 자산(7일)', sum.new_assets_7d   ?? '-', '#f59e0b', sum.changed_assets_7d!=null?`변경 ${sum.changed_assets_7d}건`:'')}
    </div>

    <!-- 취약점 심각도 분포 + 포트 TOP 10 -->
    <div class="asm-grid-2col">
      <div class="panel">
        <div class="panel-header"><span><i class="fa-solid fa-chart-pie"></i> 취약점 심각도 분포</span></div>
        <div class="panel-body">
          ${['critical','high','medium','low','info'].map(sev => {
            const cnt = bySev[sev] || 0
            const pct = totalVulnOpen > 0 ? Math.round(cnt / totalVulnOpen * 100) : 0
            return `<div class="sev-dist-row">
              ${sevBadge(sev)}
              <div class="sev-dist-bar-wrap">
                <div class="sev-dist-bar sev-bar-${sev}" style="width:${pct}%"></div>
              </div>
              <span class="sev-dist-cnt">${cnt}</span>
            </div>`
          }).join('')}
          <div style="margin-top:12px;font-size:11px;color:var(--text-muted)">
            전체 미해결 취약점 ${totalVulnOpen}건
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header"><span><i class="fa-solid fa-ethernet"></i> 오픈 포트 TOP 10</span></div>
        <div class="panel-body">${topPortHtml}</div>
      </div>
    </div>

    <!-- 위험도 상위 자산 -->
    <div class="panel" style="margin-top:16px">
      <div class="panel-header">
        <span><i class="fa-solid fa-fire-flame-curved"></i> 위험도 상위 자산</span>
        <button class="btn btn-sm btn-secondary" onclick="navigate('attack-assets')">
          <i class="fa-solid fa-arrow-right"></i> 전체 인벤토리
        </button>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="data-table">
          <thead><tr>
            <th>IP</th><th>도메인/FQDN</th><th>위험도</th><th>취약점</th><th>오픈 포트</th><th>노출</th>
          </tr></thead>
          <tbody>${topRiskHtml}</tbody>
        </table>
      </div>
    </div>

    <!-- 최근 변경이력 -->
    <div class="panel" style="margin-top:16px">
      <div class="panel-header">
        <span><i class="fa-solid fa-clock-rotate-left"></i> 최근 변경이력 (Change Log)</span>
      </div>
      <div class="panel-body" style="padding:0">
        <table class="data-table">
          <thead><tr><th>변경 유형</th><th>IP</th><th>내용</th><th>감지 시각</th></tr></thead>
          <tbody>${changeHtml}</tbody>
        </table>
      </div>
    </div>
  `
}

// ── C-2. 자산 인벤토리 ─────────────────────────────────────────

// 필터 상태
const invState = {
  page: 1, limit: 30, search: '', exposed: '', risk_min: 0, sort: 'risk'
}

async function loadAndRenderInventory(page) {
  if (page) invState.page = page
  const qs = new URLSearchParams({
    page:     invState.page,
    limit:    invState.limit,
    search:   invState.search,
    sort:     invState.sort,
    risk_min: invState.risk_min,
    ...(invState.exposed !== '' ? { exposed: invState.exposed } : {})
  }).toString()
  await loadAttackInventory(qs)
  renderAttackAssets()
}

function renderAttackAssets() {
  const content = document.getElementById('content')
  const data  = state.attackInventory || { total: 0, page: 1, limit: 30, items: [] }
  const items = data.items || []

  const rows = items.map(r => {
    const vulnSummary = [
      r.vulns.critical > 0 ? `<span class="sev-badge sev-critical">${r.vulns.critical}</span>` : '',
      r.vulns.high     > 0 ? `<span class="sev-badge sev-high">${r.vulns.high}</span>` : '',
      r.vulns.medium   > 0 ? `<span class="sev-badge sev-medium">${r.vulns.medium}</span>` : '',
      r.vulns.low      > 0 ? `<span class="sev-badge sev-low">${r.vulns.low}</span>` : '',
    ].join('') || '<span class="muted">-</span>'

    const webTitle = r.web_titles && r.web_titles.length
      ? `<span title="${esc(r.web_titles.join(' / '))}">${esc(r.web_titles[0])}</span>`
      : '<span class="muted">-</span>'

    const mainSvc = r.key_services && r.key_services.length
      ? r.key_services.slice(0, 3).map(s => `<span class="port-pill" title="${esc(s.info)}">${s.port}</span>`).join('')
      : '<span class="muted">-</span>'

    return `
      <tr class="inv-row" onclick="showAssetDetail('${esc(r.ip)}')" style="cursor:pointer" title="클릭: 상세보기">
        <td><code style="font-size:12px;font-weight:600">${esc(r.ip)}</code>
          ${r.cdn ? `<span class="tech-chip" style="font-size:9px;margin-left:4px">${esc(r.cdn)}</span>` : ''}
        </td>
        <td>${fqdnCell(r.fqdns)}</td>
        <td class="muted" style="font-size:11px">${esc(r.asn||'-')}</td>
        <td><span class="status-pill ${r.is_exposed?'pill-red':'pill-gray'}">${r.is_exposed?'외부':'내부'}</span></td>
        <td>${portPill(r.open_ports)}</td>
        <td>${mainSvc}</td>
        <td style="font-size:11px">${esc(r.os_name||'-')}</td>
        <td>${webTitle}</td>
        <td>${techChips(r.technologies)}</td>
        <td>${riskBar(r.risk_score)}</td>
        <td>${vulnSummary}</td>
        <td class="muted" style="font-size:10px">${r.first_seen ? r.first_seen.slice(0,10) : '-'}</td>
        <td class="muted" style="font-size:10px">${r.last_seen  ? r.last_seen.slice(0,10)  : '-'}</td>
        <td>${statusPill(r.status)}</td>
      </tr>`
  }).join('') || `<tr><td colspan="14" class="text-center muted">해당 조건의 자산이 없습니다</td></tr>`

  content.innerHTML = `
    <!-- 필터 바 -->
    <div class="panel" style="margin-bottom:12px">
      <div class="panel-body inv-filter-bar">
        <input type="text" id="inv-search" class="form-input inv-input"
          placeholder="IP / FQDN 검색" value="${esc(invState.search)}"
          onkeydown="if(event.key==='Enter')invApplyFilter()">
        <select id="inv-exposed" class="form-input inv-select" onchange="invApplyFilter()">
          <option value="">전체 노출</option>
          <option value="1" ${invState.exposed==='1'?'selected':''}>외부 노출</option>
          <option value="0" ${invState.exposed==='0'?'selected':''}>내부</option>
        </select>
        <select id="inv-risk" class="form-input inv-select" onchange="invApplyFilter()">
          <option value="0"  ${invState.risk_min===0 ?'selected':''}>위험도 전체</option>
          <option value="70" ${invState.risk_min===70?'selected':''}>위험도 ≥70 (High)</option>
          <option value="40" ${invState.risk_min===40?'selected':''}>위험도 ≥40 (Mid)</option>
        </select>
        <select id="inv-sort" class="form-input inv-select" onchange="invApplyFilter()">
          <option value="risk"       ${invState.sort==='risk'?'selected':''}>위험도순</option>
          <option value="ip"         ${invState.sort==='ip'?'selected':''}>IP순</option>
          <option value="first_seen" ${invState.sort==='first_seen'?'selected':''}>최초발견순</option>
          <option value="last_seen"  ${invState.sort==='last_seen'?'selected':''}>최근확인순</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="invApplyFilter()">
          <i class="fa-solid fa-magnifying-glass"></i> 검색
        </button>
        <button class="btn btn-secondary btn-sm" onclick="invResetFilter()">초기화</button>
        <span class="muted" style="margin-left:auto;font-size:11px">총 ${data.total}개 자산</span>
      </div>
    </div>

    <!-- 자산 테이블 -->
    <div class="panel">
      <div class="panel-header">
        <span><i class="fa-solid fa-table-list"></i> 자산 인벤토리 (IP 우선 · 도메인 합산)</span>
        <span class="muted" style="font-size:11px">클릭 시 자산 상세 드로어 표시</span>
      </div>
      <div class="panel-body" style="padding:0;overflow-x:auto">
        <table class="data-table inv-table">
          <thead><tr>
            <th>IP 주소</th>
            <th>도메인/FQDN</th>
            <th>ASN</th>
            <th>노출</th>
            <th>오픈 포트</th>
            <th>주요 서비스</th>
            <th>OS</th>
            <th>웹 타이틀</th>
            <th>기술스택</th>
            <th>위험도</th>
            <th>취약점</th>
            <th>최초 발견</th>
            <th>최근 확인</th>
            <th>상태</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${pager(data.page, data.limit, data.total, 'loadAndRenderInventory')}
    </div>

    <!-- 자산 상세 드로어 -->
    <div id="asset-detail-drawer" class="detail-drawer" style="display:none">
      <div class="drawer-header">
        <span id="drawer-title" class="drawer-title">자산 상세</span>
        <button class="btn btn-icon btn-sm" onclick="closeAssetDetail()"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div id="drawer-body" class="drawer-body"></div>
    </div>
  `
}

function invApplyFilter() {
  invState.search   = document.getElementById('inv-search')?.value?.trim() || ''
  invState.exposed  = document.getElementById('inv-exposed')?.value ?? ''
  invState.risk_min = parseInt(document.getElementById('inv-risk')?.value) || 0
  invState.sort     = document.getElementById('inv-sort')?.value || 'risk'
  invState.page     = 1
  loadAndRenderInventory()
}

function invResetFilter() {
  invState.search = ''; invState.exposed = ''; invState.risk_min = 0
  invState.sort = 'risk'; invState.page = 1
  loadAndRenderInventory()
}

async function showAssetDetail(ip) {
  const drawer = document.getElementById('asset-detail-drawer')
  const body   = document.getElementById('drawer-body')
  const title  = document.getElementById('drawer-title')
  if (!drawer) return
  drawer.style.display = 'flex'
  title.textContent = `자산 상세 — ${ip}`
  body.innerHTML = '<div class="loading-overlay" style="position:relative;height:80px"><div class="spinner"></div></div>'

  try {
    const d = await api(`/asm/inventory/${encodeURIComponent(ip)}`)
    const a = d.asset || {}

    const servRows = (d.services||[]).map(s => `
      <tr>
        <td>${s.port}/${s.protocol}</td>
        <td>${statusPill(s.state)}</td>
        <td>${esc(s.service_name||'-')}</td>
        <td>${esc(s.product||'-')}</td>
        <td>${esc(s.version||'-')}</td>
        <td class="muted" style="font-size:10px">${esc(s.fingerprint_source||'')}</td>
      </tr>`).join('') || `<tr><td colspan="6" class="muted text-center">서비스 없음</td></tr>`

    const httpRows = (d.http_endpoints||[]).map(h => `
      <tr>
        <td><a href="${esc(h.url)}" target="_blank" class="link-ext">${esc(h.url)}</a></td>
        <td><span class="http-status ${h.status_code>=400?'status-4xx':'status-2xx'}">${h.status_code||'-'}</span></td>
        <td style="font-size:11px">${esc(h.title||'-')}</td>
        <td style="font-size:11px">${esc(h.web_server||'-')}</td>
        <td>${techChips(h.technology)}</td>
        <td class="muted" style="font-size:10px">${h.tls_version||'-'}</td>
        <td class="muted" style="font-size:10px">${h.response_time_ms ? h.response_time_ms+'ms' : '-'}</td>
      </tr>`).join('') || `<tr><td colspan="7" class="muted text-center">HTTP 엔드포인트 없음</td></tr>`

    const vulnRows = (d.vulnerabilities||[]).map(v => `
      <tr>
        <td>${sevBadge(v.severity)}</td>
        <td style="font-size:11px"><strong>${esc(v.template_id)}</strong><br><span class="muted">${esc(v.template_name||'')}</span></td>
        <td class="muted" style="font-size:10px">${v.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(v.cve_id)}" target="_blank" class="link-ext">${esc(v.cve_id)}</a>` : '-'}</td>
        <td>${v.cvss_score != null ? v.cvss_score.toFixed(1) : '-'}</td>
        <td>${statusPill(v.status)}</td>
        <td class="muted" style="font-size:10px">${esc(v.first_seen ? v.first_seen.slice(0,10) : '-')}</td>
        <td>
          <button class="btn btn-xs btn-secondary" onclick="asmUpdateVulnStatus(${v.id},'acknowledged')">검토중</button>
          <button class="btn btn-xs btn-secondary" onclick="asmUpdateVulnStatus(${v.id},'fixed')">해결됨</button>
        </td>
      </tr>`).join('') || `<tr><td colspan="7" class="muted text-center">취약점 없음</td></tr>`

    body.innerHTML = `
      <div class="drawer-section">
        <h4 class="drawer-sec-title"><i class="fa-solid fa-circle-info"></i> 기본 정보</h4>
        <table class="detail-kv">
          <tr><td>IP</td><td><code>${esc(a.ip)}</code></td></tr>
          <tr><td>OS</td><td>${esc(a.os_name||'-')}</td></tr>
          <tr><td>ASN</td><td>${esc(a.asn||'-')}</td></tr>
          <tr><td>CDN</td><td>${esc(a.cdn||'-')}</td></tr>
          <tr><td>외부노출</td><td><span class="status-pill ${a.is_exposed?'pill-red':'pill-gray'}">${a.is_exposed?'외부':'내부'}</span></td></tr>
          <tr><td>위험도</td><td>${riskBar(a.risk_score)}</td></tr>
          <tr><td>최초발견</td><td>${a.first_seen||'-'}</td></tr>
          <tr><td>최근확인</td><td>${a.last_seen||'-'}</td></tr>
        </table>
      </div>
      <div class="drawer-section">
        <h4 class="drawer-sec-title"><i class="fa-solid fa-globe"></i> FQDN 목록 (${(d.names||[]).length}개)</h4>
        <div class="fqdn-list">${(d.names||[]).map(n =>
          `<div class="fqdn-list-item">
            <span class="fqdn-chip">${esc(n.fqdn)}</span>
            <span class="muted" style="font-size:10px">${n.record_type||''} · ${n.source||''}</span>
           </div>`).join('') || '<span class="muted">없음</span>'}</div>
      </div>
      <div class="drawer-section">
        <h4 class="drawer-sec-title"><i class="fa-solid fa-ethernet"></i> 네트워크 서비스 (${(d.services||[]).length}개)</h4>
        <table class="data-table data-table-sm">
          <thead><tr><th>포트</th><th>상태</th><th>서비스</th><th>제품</th><th>버전</th><th>출처</th></tr></thead>
          <tbody>${servRows}</tbody>
        </table>
      </div>
      <div class="drawer-section">
        <h4 class="drawer-sec-title"><i class="fa-solid fa-window-maximize"></i> HTTP 엔드포인트 (${(d.http_endpoints||[]).length}개)</h4>
        <table class="data-table data-table-sm">
          <thead><tr><th>URL</th><th>상태</th><th>타이틀</th><th>서버</th><th>기술스택</th><th>TLS</th><th>응답시간</th></tr></thead>
          <tbody>${httpRows}</tbody>
        </table>
      </div>
      <div class="drawer-section">
        <h4 class="drawer-sec-title"><i class="fa-solid fa-bug"></i> 취약점 (${(d.vulnerabilities||[]).length}개)</h4>
        <table class="data-table data-table-sm">
          <thead><tr><th>심각도</th><th>취약점명</th><th>CVE</th><th>CVSS</th><th>상태</th><th>최초발견</th><th>액션</th></tr></thead>
          <tbody>${vulnRows}</tbody>
        </table>
      </div>
    `
  } catch(e) {
    body.innerHTML = `<div class="muted" style="padding:16px">오류: ${e.message}</div>`
  }
}

function closeAssetDetail() {
  const d = document.getElementById('asset-detail-drawer')
  if (d) d.style.display = 'none'
}

// ── C-3. 취약점 현황 ────────────────────────────────────────────

const vulnState = {
  page: 1, limit: 30, search: '', severity: '', status: '', cve: '', sort: 'severity'
}

async function loadAndRenderVulns(page) {
  if (page) vulnState.page = page
  const qs = new URLSearchParams({
    page:     vulnState.page,
    limit:    vulnState.limit,
    search:   vulnState.search,
    severity: vulnState.severity,
    status:   vulnState.status,
    cve:      vulnState.cve,
    sort:     vulnState.sort,
  }).toString()
  await loadAttackVulns(qs)
  renderAttackVulns()
}

function renderAttackVulns() {
  const content = document.getElementById('content')
  const data  = state.attackVulns || { total: 0, page: 1, limit: 30, items: [] }
  const items = data.items || []

  const rows = items.map(r => `
    <tr>
      <td><code style="font-size:11px">${esc(r.ip||'-')}</code></td>
      <td style="font-size:11px">${r.fqdn ? `<span class="fqdn-chip">${esc(r.fqdn)}</span>` : '<span class="muted">-</span>'}</td>
      <td style="font-size:10px;max-width:160px;overflow:hidden;text-overflow:ellipsis">
        ${r.url ? `<a href="${esc(r.url)}" target="_blank" class="link-ext">${esc(r.url)}</a>` : '<span class="muted">-</span>'}
      </td>
      <td>${r.port || '-'}</td>
      <td class="muted" style="font-size:11px">${esc(r.service_name||'-')}</td>
      <td>
        <div style="font-size:11px"><strong>${esc(r.template_name||r.template_id)}</strong></div>
        <div class="muted" style="font-size:10px">${esc(r.template_id)}</div>
      </td>
      <td>${r.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve_id)}" target="_blank" class="link-ext cve-link">${esc(r.cve_id)}</a>` : '<span class="muted">-</span>'}</td>
      <td>${sevBadge(r.severity)}</td>
      <td>${r.cvss_score != null ? `<span class="cvss-score ${r.cvss_score>=9?'cvss-critical':r.cvss_score>=7?'cvss-high':r.cvss_score>=4?'cvss-medium':'cvss-low'}">${r.cvss_score.toFixed(1)}</span>` : '<span class="muted">-</span>'}</td>
      <td>${statusPill(r.status)}</td>
      <td class="muted" style="font-size:10px">${r.first_seen ? r.first_seen.slice(0,10) : '-'}</td>
      <td class="muted" style="font-size:10px">${r.last_seen  ? r.last_seen.slice(0,10)  : '-'}</td>
      <td>
        <select class="form-input" style="padding:2px 6px;font-size:10px;min-width:80px"
          onchange="asmUpdateVulnStatus(${r.id}, this.value)">
          <option value="open"           ${r.status==='open'?'selected':''}>OPEN</option>
          <option value="acknowledged"   ${r.status==='acknowledged'?'selected':''}>검토중</option>
          <option value="fixed"          ${r.status==='fixed'?'selected':''}>해결됨</option>
          <option value="false_positive" ${r.status==='false_positive'?'selected':''}>오탐</option>
        </select>
      </td>
    </tr>`).join('') || `<tr><td colspan="13" class="text-center muted">해당 조건의 취약점이 없습니다</td></tr>`

  content.innerHTML = `
    <!-- 필터 바 -->
    <div class="panel" style="margin-bottom:12px">
      <div class="panel-body inv-filter-bar">
        <input type="text" id="vuln-search" class="form-input inv-input"
          placeholder="IP/FQDN/취약점명 검색" value="${esc(vulnState.search)}"
          onkeydown="if(event.key==='Enter')vulnApplyFilter()">
        <select id="vuln-sev" class="form-input inv-select" onchange="vulnApplyFilter()">
          <option value="">심각도 전체</option>
          ${['critical','high','medium','low','info'].map(s =>
            `<option value="${s}" ${vulnState.severity===s?'selected':''}>${s.toUpperCase()}</option>`).join('')}
        </select>
        <select id="vuln-status" class="form-input inv-select" onchange="vulnApplyFilter()">
          <option value="">상태 전체</option>
          <option value="open"           ${vulnState.status==='open'?'selected':''}>OPEN</option>
          <option value="acknowledged"   ${vulnState.status==='acknowledged'?'selected':''}>검토중</option>
          <option value="fixed"          ${vulnState.status==='fixed'?'selected':''}>해결됨</option>
          <option value="false_positive" ${vulnState.status==='false_positive'?'selected':''}>오탐</option>
        </select>
        <input type="text" id="vuln-cve" class="form-input inv-input"
          placeholder="CVE-ID 검색" value="${esc(vulnState.cve)}"
          onkeydown="if(event.key==='Enter')vulnApplyFilter()">
        <select id="vuln-sort" class="form-input inv-select" onchange="vulnApplyFilter()">
          <option value="severity"   ${vulnState.sort==='severity'?'selected':''}>심각도순</option>
          <option value="first_seen" ${vulnState.sort==='first_seen'?'selected':''}>최초발견순</option>
          <option value="last_seen"  ${vulnState.sort==='last_seen'?'selected':''}>최근발견순</option>
          <option value="ip"         ${vulnState.sort==='ip'?'selected':''}>IP순</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="vulnApplyFilter()">
          <i class="fa-solid fa-magnifying-glass"></i> 검색
        </button>
        <button class="btn btn-secondary btn-sm" onclick="vulnResetFilter()">초기화</button>
        <span class="muted" style="margin-left:auto;font-size:11px">총 ${data.total}개 취약점</span>
      </div>
    </div>

    <!-- 취약점 테이블 -->
    <div class="panel">
      <div class="panel-header">
        <span><i class="fa-solid fa-bug"></i> 취약점 현황</span>
      </div>
      <div class="panel-body" style="padding:0;overflow-x:auto">
        <table class="data-table vuln-table">
          <thead><tr>
            <th>IP</th>
            <th>도메인</th>
            <th>URL / Target</th>
            <th>Port</th>
            <th>Service</th>
            <th>취약점명</th>
            <th>CVE</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>상태</th>
            <th>최초 발견</th>
            <th>최근 발견</th>
            <th>상태 변경</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${pager(data.page, data.limit, data.total, 'loadAndRenderVulns')}
    </div>
  `
}

function vulnApplyFilter() {
  vulnState.search   = document.getElementById('vuln-search')?.value?.trim() || ''
  vulnState.severity = document.getElementById('vuln-sev')?.value || ''
  vulnState.status   = document.getElementById('vuln-status')?.value || ''
  vulnState.cve      = document.getElementById('vuln-cve')?.value?.trim() || ''
  vulnState.sort     = document.getElementById('vuln-sort')?.value || 'severity'
  vulnState.page     = 1
  loadAndRenderVulns()
}

function vulnResetFilter() {
  vulnState.search = ''; vulnState.severity = ''; vulnState.status = ''
  vulnState.cve = ''; vulnState.sort = 'severity'; vulnState.page = 1
  loadAndRenderVulns()
}

async function asmUpdateVulnStatus(id, status) {
  try {
    await api(`/asm/vulns/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) })
    toast('상태가 업데이트되었습니다.', 'success')
    // 현재 페이지 재로드
    if (state.page === 'attack-vulns') loadAndRenderVulns()
    else if (state.page === 'attack-assets') {
      // 드로어 내 버튼에서 호출 시 드로어 다시 로드
      const ip = document.getElementById('drawer-title')?.textContent?.split('—')[1]?.trim()
      if (ip) showAssetDetail(ip)
    }
  } catch(e) { toast('업데이트 실패: ' + e.message, 'error') }
}



// ─── 유틸 ────────────────────────────────────────────────────
function esc(str) {
  if (!str) return ''
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function fmtTime(str) {
  if (!str) return '-'
  const d = new Date(str)
  if (isNaN(d)) return str
  return d.toLocaleString('ko-KR', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
