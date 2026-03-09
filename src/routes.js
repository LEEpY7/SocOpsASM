'use strict'

const express  = require('express')
const db       = require('./db')
const { probe, checkBlackboxHealth, BLACKBOX_URL, BLACKBOX_MODULE } = require('./blackbox')
const { probeAndSave, probeAll } = require('./scheduler')
const { processAlert } = require('./alerting')

const router = express.Router()

// ════════════════════════════════════════════════════════════════
//  공통
// ════════════════════════════════════════════════════════════════

router.get('/health', async (req, res) => {
  const bbHealth = await checkBlackboxHealth()
  res.json({
    status: 'ok',
    time: new Date().toISOString(),
    blackbox: { url: BLACKBOX_URL, module: BLACKBOX_MODULE, ...bbHealth }
  })
})

// ════════════════════════════════════════════════════════════════
//  모듈 A : 가용성 모니터링
// ════════════════════════════════════════════════════════════════

// ── 대시보드 상태 요약 ──────────────────────────────────────────
router.get('/status', (req, res) => {
  const rows = db.prepare(`
    SELECT
      t.id, t.name, t.url, t.category, t.sub_category, t.enabled, t.interval_sec,
      pr.probe_time,
      pr.probe_success, pr.probe_failed,
      pr.http_status_code, pr.http_version, pr.http_redirects, pr.http_content_length,
      pr.http_duration_resolve_ms, pr.http_duration_connect_ms,
      pr.http_duration_tls_ms, pr.http_duration_processing_ms, pr.http_duration_transfer_ms,
      pr.probe_duration_ms,
      pr.tls_version, pr.tls_cipher,
      pr.ssl_expiry_days, pr.ssl_earliest_expiry,
      pr.dns_lookup_ms, pr.error_msg
    FROM avail_targets t
    LEFT JOIN avail_probe_results pr ON pr.id = (
      SELECT id FROM avail_probe_results
      WHERE target_id = t.id
      ORDER BY probe_time DESC LIMIT 1
    )
    WHERE t.enabled = 1
    ORDER BY t.category, t.name
  `).all()

  const total  = rows.length
  const up     = rows.filter(r => r.probe_success === 1).length
  const down   = rows.filter(r => r.probe_time && r.probe_success === 0).length
  const noData = rows.filter(r => !r.probe_time).length

  const byCategory = {}
  for (const r of rows) {
    if (!byCategory[r.category]) byCategory[r.category] = { total: 0, up: 0, down: 0 }
    byCategory[r.category].total++
    if (r.probe_success === 1) byCategory[r.category].up++
    else if (r.probe_time)     byCategory[r.category].down++
  }

  const upRows = rows.filter(r => r.probe_success === 1 && r.probe_duration_ms)
  const avg_response_ms = upRows.length > 0
    ? Math.round(upRows.reduce((a, r) => a + r.probe_duration_ms, 0) / upRows.length)
    : null

  const ssl_warnings = rows.filter(r => r.ssl_expiry_days !== null && r.ssl_expiry_days <= 30).length

  res.json({
    summary: { total, up, down, no_data: noData,
      uptime_pct: total > 0 ? Math.round((up / total) * 100) : 0,
      avg_response_ms, ssl_warnings },
    by_category: byCategory,
    targets: rows
  })
})

// ── 타겟 CRUD ─────────────────────────────────────────────────
router.get('/targets', (req, res) => {
  res.json(db.prepare('SELECT * FROM avail_targets ORDER BY category, name').all())
})

router.post('/targets', (req, res) => {
  const { name, url, category, sub_category, interval_sec } = req.body
  if (!name || !url || !category)
    return res.status(400).json({ error: '필수 항목 누락 (name, url, category)' })
  try {
    const result = db.prepare(`
      INSERT INTO avail_targets (name, url, category, sub_category, interval_sec)
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
    UPDATE avail_targets
    SET name=@name, url=@url, category=@category, sub_category=@sub_category,
        enabled=@enabled, interval_sec=@interval_sec,
        updated_at=datetime('now','localtime')
    WHERE id=@id
  `).run({ id: req.params.id, name, url, category,
    sub_category: sub_category || null, enabled: enabled ?? 1, interval_sec: interval_sec || 60 })
  res.json({ success: true })
})

router.delete('/targets/:id', (req, res) => {
  db.prepare('DELETE FROM avail_targets WHERE id = ?').run(req.params.id)
  res.json({ success: true })
})

// ── 즉시 프로브 ──────────────────────────────────────────────
router.post('/probe/:id', async (req, res) => {
  const target = db.prepare('SELECT * FROM avail_targets WHERE id = ?').get(req.params.id)
  if (!target) return res.status(404).json({ error: '타겟 없음' })
  try {
    const result = await probeAndSave(target)
    res.json({ target_id: target.id, target_name: target.name, ...result })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

router.post('/probe-all', async (req, res) => {
  try { res.json(await probeAll()) }
  catch (e) { res.status(500).json({ error: e.message }) }
})

// ── 이력 조회 ────────────────────────────────────────────────
router.get('/history/:id', (req, res) => {
  const hours = parseInt(req.query.hours) || 168
  res.json(db.prepare(`
    SELECT * FROM avail_probe_results
    WHERE target_id = ?
      AND probe_time >= datetime('now','localtime', ? || ' hours')
    ORDER BY probe_time ASC
  `).all(req.params.id, `-${hours}`))
})

router.get('/history-summary', (req, res) => {
  res.json(db.prepare(`
    SELECT
      t.id, t.name, t.category,
      COUNT(pr.id)                                      AS total_checks,
      SUM(pr.probe_success)                             AS up_checks,
      ROUND(AVG(pr.probe_duration_ms),    1)            AS avg_response_ms,
      ROUND(MIN(pr.probe_duration_ms),    1)            AS min_response_ms,
      ROUND(MAX(pr.probe_duration_ms),    1)            AS max_response_ms,
      ROUND(AVG(pr.dns_lookup_ms),        1)            AS avg_dns_ms,
      ROUND(AVG(pr.http_duration_tls_ms), 1)            AS avg_tls_ms,
      ROUND(AVG(pr.http_duration_processing_ms), 1)     AS avg_processing_ms,
      MIN(pr.ssl_expiry_days)                           AS ssl_expiry_days
    FROM avail_targets t
    LEFT JOIN avail_probe_results pr
      ON pr.target_id = t.id
      AND pr.probe_time >= datetime('now','localtime','-7 days')
    WHERE t.enabled = 1
    GROUP BY t.id
    ORDER BY t.category, t.name
  `).all())
})

router.get('/history-chart/:id', (req, res) => {
  const hours = parseInt(req.query.hours) || 3
  res.json(db.prepare(`
    SELECT probe_time, probe_success, probe_duration_ms,
           http_status_code,
           http_duration_resolve_ms, http_duration_connect_ms,
           http_duration_tls_ms, http_duration_processing_ms, http_duration_transfer_ms,
           dns_lookup_ms, ssl_expiry_days, error_msg
    FROM avail_probe_results
    WHERE target_id = ?
      AND probe_time >= datetime('now','localtime', ? || ' hours')
    ORDER BY probe_time ASC LIMIT 180
  `).all(req.params.id, `-${hours}`))
})

// ── 카테고리 목록 ────────────────────────────────────────────
router.get('/categories', (req, res) => {
  res.json([
    { value: 'hanwha',      label: '한화생명', icon: '🔥' },
    { value: 'institution', label: '금융기관', icon: '🏛️' },
    { value: 'bank',        label: '은행',     icon: '🏦' },
    { value: 'card',        label: '카드',     icon: '💳' },
    { value: 'insurance',   label: '보험',     icon: '🛡️' },
    { value: 'securities',  label: '증권',     icon: '📈' },
    { value: 'other',       label: '기타',     icon: '🔗' }
  ])
})

// ── 원시 프로브 (디버깅) ──────────────────────────────────────
router.get('/raw-probe', async (req, res) => {
  const { url } = req.query
  if (!url) return res.status(400).json({ error: 'url 파라미터 필요' })
  res.json(await probe(url))
})

// ════════════════════════════════════════════════════════════════
//  모듈 B : 블랙박스 공격 대시보드
// ════════════════════════════════════════════════════════════════

// ── 자산 CRUD ─────────────────────────────────────────────────
router.get('/attack/assets', (req, res) => {
  res.json(db.prepare('SELECT * FROM attack_assets ORDER BY group_name, name').all())
})

router.post('/attack/assets', (req, res) => {
  const { name, asset_type, host, port, description, group_name, owner, tags } = req.body
  if (!name || !host) return res.status(400).json({ error: 'name, host 필수' })
  try {
    const result = db.prepare(`
      INSERT INTO attack_assets (name, asset_type, host, port, description, group_name, owner, tags)
      VALUES (@name, @asset_type, @host, @port, @description, @group_name, @owner, @tags)
    `).run({
      name, asset_type: asset_type || 'web', host,
      port: port || 443, description: description || null,
      group_name: group_name || null, owner: owner || null,
      tags: tags ? JSON.stringify(tags) : null
    })
    res.status(201).json({ id: result.lastInsertRowid })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

router.put('/attack/assets/:id', (req, res) => {
  const { name, asset_type, host, port, description, group_name, owner, enabled, tags } = req.body
  db.prepare(`
    UPDATE attack_assets
    SET name=@name, asset_type=@asset_type, host=@host, port=@port,
        description=@description, group_name=@group_name, owner=@owner,
        enabled=@enabled, tags=@tags, updated_at=datetime('now','localtime')
    WHERE id=@id
  `).run({
    id: req.params.id, name, asset_type: asset_type || 'web', host,
    port: port || 443, description: description || null,
    group_name: group_name || null, owner: owner || null,
    enabled: enabled ?? 1, tags: tags ? JSON.stringify(tags) : null
  })
  res.json({ success: true })
})

router.delete('/attack/assets/:id', (req, res) => {
  db.prepare('DELETE FROM attack_assets WHERE id = ?').run(req.params.id)
  res.json({ success: true })
})

// ── 이벤트 CRUD ───────────────────────────────────────────────
router.get('/attack/events', (req, res) => {
  const { severity, status, asset_id, limit = 200 } = req.query
  let sql = `
    SELECT e.*, a.name AS asset_name, a.group_name
    FROM attack_events e
    LEFT JOIN attack_assets a ON a.id = e.asset_id
    WHERE 1=1
  `
  const params = []
  if (severity) { sql += ` AND e.severity = ?`; params.push(severity) }
  if (status)   { sql += ` AND e.status = ?`;   params.push(status)   }
  if (asset_id) { sql += ` AND e.asset_id = ?`; params.push(asset_id) }
  sql += ` ORDER BY e.event_time DESC LIMIT ?`
  params.push(parseInt(limit))
  res.json(db.prepare(sql).all(...params))
})

router.post('/attack/events', (req, res) => {
  const { asset_id, event_type, severity, source_ip, source_country,
          dest_port, protocol, payload_info, status, description, raw_data } = req.body
  if (!event_type) return res.status(400).json({ error: 'event_type 필수' })
  const result = db.prepare(`
    INSERT INTO attack_events
      (asset_id, event_type, severity, source_ip, source_country,
       dest_port, protocol, payload_info, status, description, raw_data)
    VALUES
      (@asset_id, @event_type, @severity, @source_ip, @source_country,
       @dest_port, @protocol, @payload_info, @status, @description, @raw_data)
  `).run({
    asset_id: asset_id || null, event_type,
    severity: severity || 'info', source_ip: source_ip || null,
    source_country: source_country || null, dest_port: dest_port || null,
    protocol: protocol || null, payload_info: payload_info || null,
    status: status || 'open', description: description || null,
    raw_data: raw_data ? JSON.stringify(raw_data) : null
  })
  res.status(201).json({ id: result.lastInsertRowid })
})

router.patch('/attack/events/:id/status', (req, res) => {
  const { status } = req.body
  if (!['open','acknowledged','resolved','false_positive'].includes(status))
    return res.status(400).json({ error: '유효하지 않은 status 값' })
  db.prepare('UPDATE attack_events SET status=? WHERE id=?').run(status, req.params.id)
  res.json({ success: true })
})

// ── 공격 대시보드 요약 ────────────────────────────────────────
router.get('/attack/summary', (req, res) => {
  const totalAssets  = db.prepare('SELECT COUNT(*) AS c FROM attack_assets WHERE enabled=1').get().c
  const totalEvents  = db.prepare('SELECT COUNT(*) AS c FROM attack_events').get().c
  const openEvents   = db.prepare("SELECT COUNT(*) AS c FROM attack_events WHERE status='open'").get().c
  const criticalOpen = db.prepare("SELECT COUNT(*) AS c FROM attack_events WHERE severity='critical' AND status='open'").get().c
  const highOpen     = db.prepare("SELECT COUNT(*) AS c FROM attack_events WHERE severity='high' AND status='open'").get().c

  const bySeverity = db.prepare(`
    SELECT severity, COUNT(*) AS cnt
    FROM attack_events WHERE status='open'
    GROUP BY severity
  `).all()

  const byType = db.prepare(`
    SELECT event_type, COUNT(*) AS cnt
    FROM attack_events WHERE status='open'
    GROUP BY event_type ORDER BY cnt DESC LIMIT 10
  `).all()

  const recent = db.prepare(`
    SELECT e.*, a.name AS asset_name
    FROM attack_events e
    LEFT JOIN attack_assets a ON a.id = e.asset_id
    ORDER BY e.event_time DESC LIMIT 10
  `).all()

  res.json({ totalAssets, totalEvents, openEvents, criticalOpen, highOpen,
             bySeverity, byType, recent })
})

// ── 일별 통계 ─────────────────────────────────────────────────
router.get('/attack/stats', (req, res) => {
  const days = parseInt(req.query.days) || 7
  res.json(db.prepare(`
    SELECT DATE(event_time) AS date,
           severity,
           COUNT(*) AS cnt
    FROM attack_events
    WHERE event_time >= datetime('now','localtime', ? || ' days')
    GROUP BY DATE(event_time), severity
    ORDER BY date ASC
  `).all(`-${days}`))
})

// ════════════════════════════════════════════════════════════════
//  공통 : 경보 관리
// ════════════════════════════════════════════════════════════════

router.get('/alerts', (req, res) => {
  const { module } = req.query
  let sql = 'SELECT * FROM alert_configs'
  const params = []
  if (module) { sql += ' WHERE module=?'; params.push(module) }
  res.json(db.prepare(sql + ' ORDER BY id').all(...params))
})

router.post('/alerts', (req, res) => {
  const { name, module, to_email, enabled, down_notify, threshold_ms, ssl_warn_days, severity_filter } = req.body
  if (!name || !to_email) return res.status(400).json({ error: 'name, to_email 필수' })
  const result = db.prepare(`
    INSERT INTO alert_configs
      (name, module, to_email, enabled, down_notify, threshold_ms, ssl_warn_days, severity_filter)
    VALUES
      (@name, @module, @to_email, @enabled, @down_notify, @threshold_ms, @ssl_warn_days, @severity_filter)
  `).run({
    name, module: module || 'availability', to_email,
    enabled: enabled ?? 1, down_notify: down_notify ?? 1,
    threshold_ms: threshold_ms ?? 3000, ssl_warn_days: ssl_warn_days ?? 30,
    severity_filter: severity_filter || 'critical,high'
  })
  res.status(201).json({ id: result.lastInsertRowid })
})

router.put('/alerts/:id', (req, res) => {
  const { name, module, to_email, enabled, down_notify, threshold_ms, ssl_warn_days, severity_filter } = req.body
  db.prepare(`
    UPDATE alert_configs
    SET name=@name, module=@module, to_email=@to_email, enabled=@enabled,
        down_notify=@down_notify, threshold_ms=@threshold_ms,
        ssl_warn_days=@ssl_warn_days, severity_filter=@severity_filter
    WHERE id=@id
  `).run({
    id: req.params.id, name, module: module || 'availability', to_email,
    enabled: enabled ?? 1, down_notify: down_notify ?? 1,
    threshold_ms: threshold_ms ?? 3000, ssl_warn_days: ssl_warn_days ?? 30,
    severity_filter: severity_filter || 'critical,high'
  })
  res.json({ success: true })
})

router.delete('/alerts/:id', (req, res) => {
  db.prepare('DELETE FROM alert_configs WHERE id = ?').run(req.params.id)
  res.json({ success: true })
})

router.get('/alert-history', (req, res) => {
  const { module } = req.query
  let sql = `
    SELECT ah.*, ac.name AS alert_name
    FROM alert_history ah
    LEFT JOIN alert_configs ac ON ac.id = ah.alert_config_id
    WHERE 1=1
  `
  const params = []
  if (module) { sql += ' AND ah.module=?'; params.push(module) }
  sql += ' ORDER BY ah.sent_at DESC LIMIT 200'
  // target_name: availability → avail_targets, attack → attack_assets
  const rows = db.prepare(sql).all(...params).map(r => {
    if (r.module === 'attack') {
      const a = r.target_id ? db.prepare('SELECT name FROM attack_assets WHERE id=?').get(r.target_id) : null
      return { ...r, target_name: a ? a.name : null }
    } else {
      const t = r.target_id ? db.prepare('SELECT name FROM avail_targets WHERE id=?').get(r.target_id) : null
      return { ...r, target_name: t ? t.name : null }
    }
  })
  res.json(rows)
})

router.post('/alerts/:id/test', async (req, res) => {
  const { sendMail } = require('./alerting')
  const cfg = db.prepare('SELECT * FROM alert_configs WHERE id = ?').get(req.params.id)
  if (!cfg) return res.status(404).json({ error: '알림 설정 없음' })
  const ok = await sendMail(
    cfg.to_email,
    '🔔 [한화생명 보안관제센터] 알림 테스트',
    `<html><body style="font-family:sans-serif;background:#1a1c23;color:#d4d6e0;padding:20px">
      <div style="background:#22252f;border:1px solid #353849;border-radius:8px;padding:20px;max-width:500px;margin:0 auto">
        <h2 style="color:#f37321">🔔 한화생명 보안관제센터 알림 테스트</h2>
        <p>이 메일은 알림 설정 테스트 메일입니다.</p>
        <table style="width:100%;margin-top:16px;font-size:13px">
          <tr><td style="color:#8a8fa8;padding:4px 0">알림명</td><td>${cfg.name}</td></tr>
          <tr><td style="color:#8a8fa8;padding:4px 0">모듈</td><td>${cfg.module}</td></tr>
          <tr><td style="color:#8a8fa8;padding:4px 0">수신 이메일</td><td>${cfg.to_email}</td></tr>
          <tr><td style="color:#8a8fa8;padding:4px 0">발송 시간</td><td>${new Date().toLocaleString('ko-KR')}</td></tr>
        </table>
      </div>
    </body></html>`
  )
  if (ok) res.json({ success: true, message: `${cfg.to_email}으로 테스트 메일을 발송했습니다.` })
  else    res.status(500).json({ error: 'SMTP 미설정 또는 발송 실패' })
})

module.exports = router
