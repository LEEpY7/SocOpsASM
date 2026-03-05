'use strict'

const express  = require('express')
const db       = require('./db')
const { probe, checkBlackboxHealth, BLACKBOX_URL, BLACKBOX_MODULE } = require('./blackbox')
const { probeAndSave, probeAll } = require('./scheduler')
const { processAlert } = require('./alerting')

const router = express.Router()

// ─── 헬스체크 ────────────────────────────────────────────────────
router.get('/health', async (req, res) => {
  const bbHealth = await checkBlackboxHealth()
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    blackbox: {
      url: BLACKBOX_URL,
      module: BLACKBOX_MODULE,
      ...bbHealth
    }
  })
})

// ─── 대시보드 상태 요약 ─────────────────────────────────────────
router.get('/status', (req, res) => {
  // 각 타겟의 최신 프로브 결과 1건씩 조회
  const rows = db.prepare(`
    SELECT
      t.id, t.name, t.url, t.category, t.sub_category, t.enabled, t.interval_sec,
      pr.probe_time,
      pr.probe_success,
      pr.probe_failed,
      pr.http_status_code,
      pr.http_version,
      pr.http_redirects,
      pr.http_content_length,
      pr.http_duration_resolve_ms,
      pr.http_duration_connect_ms,
      pr.http_duration_tls_ms,
      pr.http_duration_processing_ms,
      pr.http_duration_transfer_ms,
      pr.probe_duration_ms,
      pr.tls_version,
      pr.tls_cipher,
      pr.ssl_expiry_days,
      pr.ssl_earliest_expiry,
      pr.dns_lookup_ms,
      pr.error_msg
    FROM targets t
    LEFT JOIN probe_results pr ON pr.id = (
      SELECT id FROM probe_results
      WHERE target_id = t.id
      ORDER BY probe_time DESC LIMIT 1
    )
    WHERE t.enabled = 1
    ORDER BY t.category, t.name
  `).all()

  // 요약 집계
  const total  = rows.length
  const up     = rows.filter(r => r.probe_success === 1).length
  const down   = rows.filter(r => r.probe_time && r.probe_success === 0).length
  const noData = rows.filter(r => !r.probe_time).length

  // 카테고리별 통계
  const byCategory = {}
  for (const r of rows) {
    if (!byCategory[r.category]) byCategory[r.category] = { total: 0, up: 0, down: 0 }
    byCategory[r.category].total++
    if (r.probe_success === 1) byCategory[r.category].up++
    else if (r.probe_time)     byCategory[r.category].down++
  }

  // 평균 응답시간 (UP인 대상만)
  const upRows = rows.filter(r => r.probe_success === 1 && r.probe_duration_ms)
  const avg_response_ms = upRows.length > 0
    ? Math.round(upRows.reduce((a, r) => a + r.probe_duration_ms, 0) / upRows.length)
    : null

  // SSL 만료 임박 (30일 이하)
  const ssl_warnings = rows.filter(r => r.ssl_expiry_days !== null && r.ssl_expiry_days <= 30).length

  res.json({
    summary: {
      total, up, down, no_data: noData,
      uptime_pct: total > 0 ? Math.round((up / total) * 100) : 0,
      avg_response_ms,
      ssl_warnings
    },
    by_category: byCategory,
    targets: rows
  })
})

// ─── 타겟 CRUD ──────────────────────────────────────────────────
router.get('/targets', (req, res) => {
  const rows = db.prepare('SELECT * FROM targets ORDER BY category, name').all()
  res.json(rows)
})

router.post('/targets', (req, res) => {
  const { name, url, category, sub_category, interval_sec } = req.body
  if (!name || !url || !category)
    return res.status(400).json({ error: '필수 항목 누락 (name, url, category)' })

  try {
    const result = db.prepare(`
      INSERT INTO targets (name, url, category, sub_category, interval_sec)
      VALUES (@name, @url, @category, @sub_category, @interval_sec)
    `).run({ name, url, category, sub_category: sub_category || null, interval_sec: interval_sec || 60 })
    res.status(201).json({ id: result.lastInsertRowid, name, url, category })
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: '이미 등록된 URL입니다' })
    res.status(500).json({ error: e.message })
  }
})

router.put('/targets/:id', (req, res) => {
  const { name, url, category, sub_category, enabled, interval_sec } = req.body
  db.prepare(`
    UPDATE targets
    SET name=@name, url=@url, category=@category, sub_category=@sub_category,
        enabled=@enabled, interval_sec=@interval_sec,
        updated_at=datetime('now','localtime')
    WHERE id=@id
  `).run({ id: req.params.id, name, url, category, sub_category: sub_category || null, enabled: enabled ?? 1, interval_sec: interval_sec || 60 })
  res.json({ success: true })
})

router.delete('/targets/:id', (req, res) => {
  db.prepare('DELETE FROM targets WHERE id = ?').run(req.params.id)
  res.json({ success: true })
})

// ─── 즉시 프로브 ────────────────────────────────────────────────
router.post('/probe/:id', async (req, res) => {
  const target = db.prepare('SELECT * FROM targets WHERE id = ?').get(req.params.id)
  if (!target) return res.status(404).json({ error: '타겟 없음' })

  try {
    const result = await probeAndSave(target)
    res.json({ target_id: target.id, target_name: target.name, ...result })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ─── 전체 즉시 프로브 ───────────────────────────────────────────
router.post('/probe-all', async (req, res) => {
  try {
    const result = await probeAll()
    res.json(result)
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ─── 이력 조회 ──────────────────────────────────────────────────
// GET /api/history/:id?hours=168
router.get('/history/:id', (req, res) => {
  const hours = parseInt(req.query.hours) || 168
  const rows = db.prepare(`
    SELECT *
    FROM probe_results
    WHERE target_id = ?
      AND probe_time >= datetime('now', 'localtime', ? || ' hours')
    ORDER BY probe_time ASC
  `).all(req.params.id, `-${hours}`)
  res.json(rows)
})

// GET /api/history-summary  7일 집계
router.get('/history-summary', (req, res) => {
  const rows = db.prepare(`
    SELECT
      t.id, t.name, t.category,
      COUNT(pr.id)           AS total_checks,
      SUM(pr.probe_success)  AS up_checks,
      ROUND(AVG(pr.probe_duration_ms), 1)  AS avg_response_ms,
      ROUND(MIN(pr.probe_duration_ms), 1)  AS min_response_ms,
      ROUND(MAX(pr.probe_duration_ms), 1)  AS max_response_ms,
      ROUND(AVG(pr.dns_lookup_ms), 1)      AS avg_dns_ms,
      ROUND(AVG(pr.http_duration_tls_ms), 1) AS avg_tls_ms,
      ROUND(AVG(pr.http_duration_processing_ms), 1) AS avg_processing_ms,
      MIN(pr.ssl_expiry_days) AS ssl_expiry_days
    FROM targets t
    LEFT JOIN probe_results pr
      ON pr.target_id = t.id
      AND pr.probe_time >= datetime('now', 'localtime', '-7 days')
    WHERE t.enabled = 1
    GROUP BY t.id
    ORDER BY t.category, t.name
  `).all()
  res.json(rows)
})

// GET /api/history-chart/:id  차트용 시계열 (최대 500포인트)
router.get('/history-chart/:id', (req, res) => {
  const hours = parseInt(req.query.hours) || 24
  const rows = db.prepare(`
    SELECT
      probe_time,
      probe_success,
      probe_duration_ms,
      http_status_code,
      http_duration_resolve_ms,
      http_duration_connect_ms,
      http_duration_tls_ms,
      http_duration_processing_ms,
      http_duration_transfer_ms,
      dns_lookup_ms,
      ssl_expiry_days,
      error_msg
    FROM probe_results
    WHERE target_id = ?
      AND probe_time >= datetime('now', 'localtime', ? || ' hours')
    ORDER BY probe_time ASC
    LIMIT 500
  `).all(req.params.id, `-${hours}`)
  res.json(rows)
})

// ─── 알림 설정 CRUD ─────────────────────────────────────────────
router.get('/alerts', (req, res) => {
  res.json(db.prepare('SELECT * FROM alert_configs ORDER BY id').all())
})

router.post('/alerts', (req, res) => {
  const { name, to_email, enabled, down_notify, threshold_ms, ssl_warn_days } = req.body
  if (!name || !to_email) return res.status(400).json({ error: 'name, to_email 필수' })
  const result = db.prepare(`
    INSERT INTO alert_configs (name, to_email, enabled, down_notify, threshold_ms, ssl_warn_days)
    VALUES (@name, @to_email, @enabled, @down_notify, @threshold_ms, @ssl_warn_days)
  `).run({
    name, to_email,
    enabled:      enabled      ?? 1,
    down_notify:  down_notify  ?? 1,
    threshold_ms: threshold_ms ?? 3000,
    ssl_warn_days: ssl_warn_days ?? 30
  })
  res.status(201).json({ id: result.lastInsertRowid })
})

router.put('/alerts/:id', (req, res) => {
  const { name, to_email, enabled, down_notify, threshold_ms, ssl_warn_days } = req.body
  db.prepare(`
    UPDATE alert_configs
    SET name=@name, to_email=@to_email, enabled=@enabled,
        down_notify=@down_notify, threshold_ms=@threshold_ms, ssl_warn_days=@ssl_warn_days
    WHERE id=@id
  `).run({ id: req.params.id, name, to_email, enabled: enabled ?? 1, down_notify: down_notify ?? 1, threshold_ms: threshold_ms ?? 3000, ssl_warn_days: ssl_warn_days ?? 30 })
  res.json({ success: true })
})

router.delete('/alerts/:id', (req, res) => {
  db.prepare('DELETE FROM alert_configs WHERE id = ?').run(req.params.id)
  res.json({ success: true })
})

// ─── 알림 이력 ──────────────────────────────────────────────────
router.get('/alert-history', (req, res) => {
  const rows = db.prepare(`
    SELECT ah.*, t.name AS target_name, ac.name AS alert_name
    FROM alert_history ah
    LEFT JOIN targets t  ON t.id  = ah.target_id
    LEFT JOIN alert_configs ac ON ac.id = ah.alert_config_id
    ORDER BY ah.sent_at DESC LIMIT 200
  `).all()
  res.json(rows)
})

// ─── 카테고리 목록 ───────────────────────────────────────────────
router.get('/categories', (req, res) => {
  res.json([
    { value: 'hanwha',      label: '한화생명',   icon: '🔥' },
    { value: 'institution', label: '금융기관',   icon: '🏛️' },
    { value: 'bank',        label: '은행',       icon: '🏦' },
    { value: 'card',        label: '카드',       icon: '💳' },
    { value: 'insurance',   label: '보험',       icon: '🛡️' },
    { value: 'securities',  label: '증권',       icon: '📈' },
    { value: 'other',       label: '기타',       icon: '🔗' }
  ])
})

// ─── Blackbox Exporter 원시 메트릭 조회 (디버깅용) ──────────────
router.get('/raw-probe', async (req, res) => {
  const { url } = req.query
  if (!url) return res.status(400).json({ error: 'url 파라미터 필요' })
  const result = await probe(url)
  res.json(result)
})

// ─── 알림 테스트 발송 ────────────────────────────────────────────
router.post('/alerts/:id/test', async (req, res) => {
  const { sendMail } = require('./alerting')
  const cfg = db.prepare('SELECT * FROM alert_configs WHERE id = ?').get(req.params.id)
  if (!cfg) return res.status(404).json({ error: '알림 설정 없음' })

  const ok = await sendMail(
    cfg.to_email,
    '🔔 [FinMonitor] 알림 테스트',
    `<html><body style="font-family:sans-serif;background:#1a1c23;color:#d4d6e0;padding:20px">
      <div style="background:#22252f;border:1px solid #353849;border-radius:8px;padding:20px;max-width:500px;margin:0 auto">
        <h2 style="color:#5b70f5">✅ FinMonitor 알림 테스트</h2>
        <p>이 메일은 알림 설정 테스트 메일입니다.</p>
        <table style="width:100%;margin-top:16px;font-size:13px">
          <tr><td style="color:#8a8fa8;padding:4px 0">알림명</td><td>${cfg.name}</td></tr>
          <tr><td style="color:#8a8fa8;padding:4px 0">수신 이메일</td><td>${cfg.to_email}</td></tr>
          <tr><td style="color:#8a8fa8;padding:4px 0">발송 시간</td><td>${new Date().toLocaleString('ko-KR')}</td></tr>
        </table>
        <p style="margin-top:16px;color:#5a5f78;font-size:11px">FinMonitor — 금융권 웹 가용성 모니터링</p>
      </div>
    </body></html>`
  )

  if (ok) {
    res.json({ success: true, message: `${cfg.to_email}으로 테스트 메일을 발송했습니다.` })
  } else {
    res.status(500).json({ error: 'SMTP_USER/SMTP_PASS 미설정 또는 발송 실패' })
  }
})

module.exports = router
