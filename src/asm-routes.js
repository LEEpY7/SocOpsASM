'use strict'

const express = require('express')
const { asmDb } = require('./asm-db')

const router = express.Router()

// ════════════════════════════════════════════════════════════════
//  요약 대시보드 API
// ════════════════════════════════════════════════════════════════
router.get('/summary', (req, res) => {
  try {
    const totalAssets   = asmDb.prepare("SELECT COUNT(*) AS c FROM asset_current").get().c
    const exposedIPs    = asmDb.prepare("SELECT COUNT(*) AS c FROM asset_current WHERE is_exposed=1").get().c
    const exposedFQDNs  = asmDb.prepare("SELECT COUNT(*) AS c FROM asset_name an JOIN asset a ON a.id=an.asset_id WHERE a.is_exposed=1").get().c
    const withPorts     = asmDb.prepare("SELECT COUNT(*) AS c FROM asset_current WHERE json_array_length(open_ports) > 0").get().c
    const withWeb       = asmDb.prepare("SELECT COUNT(DISTINCT asset_id) AS c FROM http_endpoint").get().c
    const newAssets7d   = asmDb.prepare("SELECT COUNT(*) AS c FROM asset WHERE first_seen >= datetime('now','localtime','-7 days')").get().c
    const changedAssets7d = asmDb.prepare("SELECT COUNT(*) AS c FROM asset_change_log WHERE detected_at >= datetime('now','localtime','-7 days')").get().c

    // 취약점 집계
    const vulnSev = asmDb.prepare(`
      SELECT severity, COUNT(*) AS cnt
      FROM vulnerability_finding
      WHERE status NOT IN ('fixed','false_positive')
      GROUP BY severity
    `).all()
    const vulnMap = { critical:0, high:0, medium:0, low:0, info:0 }
    vulnSev.forEach(r => { if (vulnMap[r.severity] !== undefined) vulnMap[r.severity] = r.cnt })

    // 오픈 포트 TOP 10
    const topPorts = asmDb.prepare(`
      SELECT port, COUNT(*) AS cnt
      FROM network_service
      WHERE state='open'
      GROUP BY port ORDER BY cnt DESC LIMIT 10
    `).all()

    // 신규 자산 추이 (7일)
    const newTrend = asmDb.prepare(`
      SELECT DATE(first_seen) AS date, COUNT(*) AS cnt
      FROM asset
      WHERE first_seen >= datetime('now','localtime','-7 days')
      GROUP BY DATE(first_seen)
      ORDER BY date ASC
    `).all()

    // 위험도 상위 자산
    const topRisk = asmDb.prepare(`
      SELECT ac.ip, ac.fqdns, ac.risk_score,
             ac.vuln_critical, ac.vuln_high, ac.vuln_medium,
             ac.open_ports, ac.is_exposed
      FROM asset_current ac
      ORDER BY ac.risk_score DESC, ac.vuln_critical DESC
      LIMIT 10
    `).all().map(r => ({
      ...r,
      fqdns: parseJSON(r.fqdns, []),
      open_ports: parseJSON(r.open_ports, [])
    }))

    // 최근 변경이력
    const recentChanges = asmDb.prepare(`
      SELECT * FROM asset_change_log
      ORDER BY detected_at DESC LIMIT 10
    `).all().map(r => ({ ...r, detail: parseJSON(r.detail, {}) }))

    res.json({
      summary: {
        total_assets: totalAssets,
        exposed_ips: exposedIPs,
        exposed_fqdns: exposedFQDNs,
        assets_with_ports: withPorts,
        assets_with_web: withWeb,
        vuln_critical: vulnMap.critical,
        vuln_high: vulnMap.high,
        vuln_medium: vulnMap.medium,
        vuln_low: vulnMap.low,
        vuln_info: vulnMap.info,
        new_assets_7d: newAssets7d,
        changed_assets_7d: changedAssets7d,
      },
      top_ports: topPorts,
      vuln_by_severity: vulnSev,
      new_asset_trend: newTrend,
      top_risk_assets: topRisk,
      recent_changes: recentChanges,
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ════════════════════════════════════════════════════════════════
//  자산 인벤토리 API
// ════════════════════════════════════════════════════════════════
/**
 * GET /api/asm/inventory
 * query: page(1), limit(50), search, exposed(0/1), risk_min, sort(ip|risk|first_seen)
 */
router.get('/inventory', (req, res) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page)  || 1)
    const limit    = Math.min(200, parseInt(req.query.limit) || 50)
    const offset   = (page - 1) * limit
    const search   = req.query.search  || ''
    const exposed  = req.query.exposed
    const riskMin  = parseFloat(req.query.risk_min) || 0
    const sort     = req.query.sort || 'risk'

    const sortMap = {
      ip: 'ac.ip ASC',
      risk: 'ac.risk_score DESC, ac.vuln_critical DESC',
      first_seen: 'a.first_seen DESC',
      last_seen: 'a.last_seen DESC'
    }
    const orderBy = sortMap[sort] || sortMap.risk

    let where = 'WHERE ac.risk_score >= @riskMin'
    const params = { riskMin, limit, offset, search: `%${search}%` }

    if (exposed !== undefined) {
      where += ' AND ac.is_exposed = @exposed'
      params.exposed = parseInt(exposed)
    }
    if (search) {
      where += ' AND (ac.ip LIKE @search OR ac.fqdns LIKE @search)'
    }

    const total = asmDb.prepare(`
      SELECT COUNT(*) AS c
      FROM asset_current ac
      JOIN asset a ON a.ip = ac.ip
      ${where}
    `).get(params).c

    const rows = asmDb.prepare(`
      SELECT
        ac.ip,
        ac.fqdns,
        ac.root_domains,
        ac.is_exposed,
        ac.is_internal,
        ac.asn,
        ac.cdn,
        ac.os_name,
        ac.open_ports,
        ac.service_summary,
        ac.web_titles,
        ac.technologies,
        ac.risk_score,
        ac.vuln_critical, ac.vuln_high, ac.vuln_medium, ac.vuln_low, ac.vuln_info,
        ac.first_seen,
        ac.last_seen,
        ac.status
      FROM asset_current ac
      JOIN asset a ON a.ip = ac.ip
      ${where}
      ORDER BY ${orderBy}
      LIMIT @limit OFFSET @offset
    `).all(params)

    // JSON 파싱 + 서비스 구조화
    const items = rows.map(r => {
      const fqdns        = parseJSON(r.fqdns, [])
      const rootDomains  = parseJSON(r.root_domains, [])
      const openPorts    = parseJSON(r.open_ports, [])
      const svcSummary   = parseJSON(r.service_summary, {})
      const webTitles    = parseJSON(r.web_titles, [])
      const techs        = parseJSON(r.technologies, [])

      // 주요 서비스 (80/443/8080 우선)
      const keySvcs = [80, 443, 8080, 8443, 22, 3306, 3389]
        .filter(p => openPorts.includes(p))
        .map(p => ({ port: p, info: svcSummary[p] || '' }))

      return {
        ip: r.ip,
        fqdns,
        root_domains: rootDomains,
        is_exposed: !!r.is_exposed,
        is_internal: !!r.is_internal,
        asn: r.asn,
        cdn: r.cdn,
        os_name: r.os_name,
        open_ports: openPorts,
        key_services: keySvcs,
        service_summary: svcSummary,
        web_titles: webTitles,
        technologies: techs,
        risk_score: r.risk_score,
        vulns: {
          critical: r.vuln_critical,
          high:     r.vuln_high,
          medium:   r.vuln_medium,
          low:      r.vuln_low,
          info:     r.vuln_info,
        },
        first_seen: r.first_seen,
        last_seen:  r.last_seen,
        status: r.status,
      }
    })

    res.json({ total, page, limit, items })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// GET /api/asm/inventory/:ip  — 단일 자산 상세
router.get('/inventory/:ip', (req, res) => {
  try {
    const ip = req.params.ip
    const asset = asmDb.prepare('SELECT * FROM asset WHERE ip = ?').get(ip)
    if (!asset) return res.status(404).json({ error: '자산 없음' })

    const names    = asmDb.prepare('SELECT * FROM asset_name WHERE asset_id = ?').all(asset.id)
    const dnsRecs  = asmDb.prepare(`SELECT * FROM dns_record WHERE fqdn IN (SELECT fqdn FROM asset_name WHERE asset_id = ?) ORDER BY fqdn, record_type`).all(asset.id)
    const services = asmDb.prepare("SELECT * FROM network_service WHERE asset_id = ? ORDER BY port").all(asset.id)
    const http     = asmDb.prepare('SELECT * FROM http_endpoint WHERE asset_id = ? ORDER BY url').all(asset.id)
    const vulns    = asmDb.prepare(`SELECT * FROM vulnerability_finding WHERE asset_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`).all(asset.id)
    const changes  = asmDb.prepare('SELECT * FROM asset_change_log WHERE asset_ip = ? ORDER BY detected_at DESC LIMIT 20').all(ip)

    res.json({
      asset,
      names,
      dns_records: dnsRecs,
      services,
      http_endpoints: http.map(h => ({ ...h, technology: parseJSON(h.technology, []) })),
      vulnerabilities: vulns,
      changes: changes.map(c => ({ ...c, detail: parseJSON(c.detail, {}) })),
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ════════════════════════════════════════════════════════════════
//  취약점 현황 API
// ════════════════════════════════════════════════════════════════
/**
 * GET /api/asm/vulns
 * query: page, limit, severity, status, cve, search, sort
 */
router.get('/vulns', (req, res) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page)  || 1)
    const limit    = Math.min(200, parseInt(req.query.limit) || 50)
    const offset   = (page - 1) * limit
    const severity = req.query.severity || ''
    const status   = req.query.status   || ''
    const cve      = req.query.cve      || ''
    const search   = req.query.search   || ''
    const sort     = req.query.sort     || 'severity'

    const sortMap = {
      severity:   "CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC, v.cvss_score DESC",
      first_seen: 'v.first_seen DESC',
      last_seen:  'v.last_seen DESC',
      ip:         'v.ip ASC',
    }
    const orderBy = sortMap[sort] || sortMap.severity

    let where = "WHERE 1=1"
    const params = { limit, offset }

    if (severity) { where += ' AND v.severity = @severity'; params.severity = severity }
    if (status)   { where += ' AND v.status   = @status';   params.status   = status   }
    if (cve)      { where += ' AND v.cve_id   LIKE @cve';   params.cve      = `%${cve}%` }
    if (search) {
      where += ' AND (v.ip LIKE @search OR v.fqdn LIKE @search OR v.template_name LIKE @search OR v.template_id LIKE @search)'
      params.search = `%${search}%`
    }

    const total = asmDb.prepare(`SELECT COUNT(*) AS c FROM vulnerability_finding v ${where}`).get(params).c

    const rows = asmDb.prepare(`
      SELECT
        v.id, v.ip, v.fqdn, v.url, v.port, v.service_name,
        v.template_id, v.template_name,
        v.severity, v.cvss_score, v.cve_id, v.cwe_id,
        v.tags, v.matched_at, v.extracted_results,
        v.status, v.first_seen, v.last_seen
      FROM vulnerability_finding v
      ${where}
      ORDER BY ${orderBy}
      LIMIT @limit OFFSET @offset
    `).all(params)

    res.json({
      total, page, limit,
      items: rows.map(r => ({
        ...r,
        tags: r.tags ? r.tags.split(',') : [],
        extracted_results: parseJSON(r.extracted_results, null),
      }))
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// PATCH /api/asm/vulns/:id/status — 상태 변경
router.patch('/vulns/:id/status', (req, res) => {
  const valid = ['open','acknowledged','fixed','false_positive']
  const { status } = req.body
  if (!valid.includes(status)) return res.status(400).json({ error: '유효하지 않은 status' })
  asmDb.prepare('UPDATE vulnerability_finding SET status=? WHERE id=?').run(status, req.params.id)
  res.json({ success: true })
})

// ════════════════════════════════════════════════════════════════
//  변경 이력 API
// ════════════════════════════════════════════════════════════════
router.get('/changes', (req, res) => {
  try {
    const limit = Math.min(200, parseInt(req.query.limit) || 50)
    const rows = asmDb.prepare(`
      SELECT * FROM asset_change_log
      ORDER BY detected_at DESC LIMIT ?
    `).all(limit)
    res.json(rows.map(r => ({ ...r, detail: parseJSON(r.detail, {}) })))
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ════════════════════════════════════════════════════════════════
//  유틸
// ════════════════════════════════════════════════════════════════
function parseJSON(str, fallback) {
  if (!str) return fallback
  try { return JSON.parse(str) } catch { return fallback }
}

module.exports = router
