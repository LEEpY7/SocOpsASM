'use strict'

const cron      = require('node-cron')
const db        = require('./db')
const { probe } = require('./blackbox')
const { processAlert } = require('./alerting')

// DB prepared statements
const getTargets = db.prepare('SELECT * FROM avail_targets WHERE enabled = 1')

const insertResult = db.prepare(`
  INSERT INTO avail_probe_results (
    target_id, probe_time,
    probe_success, probe_failed,
    http_status_code, http_version, http_redirects, http_content_length,
    http_duration_resolve_ms, http_duration_connect_ms, http_duration_tls_ms,
    http_duration_processing_ms, http_duration_transfer_ms,
    probe_duration_ms,
    tls_version, tls_cipher,
    ssl_expiry_days, ssl_earliest_expiry,
    dns_lookup_ms,
    error_msg
  ) VALUES (
    @target_id, @probe_time,
    @probe_success, @probe_failed,
    @http_status_code, @http_version, @http_redirects, @http_content_length,
    @http_duration_resolve_ms, @http_duration_connect_ms, @http_duration_tls_ms,
    @http_duration_processing_ms, @http_duration_transfer_ms,
    @probe_duration_ms,
    @tls_version, @tls_cipher,
    @ssl_expiry_days, @ssl_earliest_expiry,
    @dns_lookup_ms,
    @error_msg
  )
`)

const cleanup = db.prepare(`
  DELETE FROM avail_probe_results
  WHERE probe_time < TO_CHAR(CURRENT_TIMESTAMP - INTERVAL '7 days','YYYY-MM-DD HH24:MI:SS')
`)

// 동시 실행 방지 플래그
let isRunning = false

/**
 * 단일 타겟 프로브 및 DB 저장
 */
async function probeAndSave(target) {
  const result = await probe(target.url)
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19)

  insertResult.run({
    target_id:    target.id,
    probe_time:   now,
    probe_success: result.probe_success ? 1 : 0,
    probe_failed:  result.probe_failed  ? 1 : 0,
    http_status_code: result.http_status_code,
    http_version:     result.http_version,
    http_redirects:   result.http_redirects,
    http_content_length: result.http_content_length,
    http_duration_resolve_ms:    result.http_duration_resolve_ms,
    http_duration_connect_ms:    result.http_duration_connect_ms,
    http_duration_tls_ms:        result.http_duration_tls_ms,
    http_duration_processing_ms: result.http_duration_processing_ms,
    http_duration_transfer_ms:   result.http_duration_transfer_ms,
    probe_duration_ms: result.probe_duration_ms,
    tls_version:  result.tls_version,
    tls_cipher:   result.tls_cipher,
    ssl_expiry_days:    result.ssl_expiry_days,
    ssl_earliest_expiry: result.ssl_earliest_expiry,
    dns_lookup_ms: result.dns_lookup_ms,
    error_msg:    result.error_msg
  })

  // 알림 처리 (비동기, 실패해도 계속)
  processAlert(target, result).catch(err =>
    console.error(`[알림 오류] ${target.name}:`, err.message)
  )

  return result
}

/**
 * 전체 활성 타겟 일괄 프로브
 * - Promise.all로 병렬 실행 (최대 동시 10개)
 */
async function probeAll() {
  if (isRunning) {
    console.log('[스케줄러] 이전 프로브 실행 중 → 건너뜀')
    return { skipped: true }
  }

  isRunning = true
  const start = Date.now()
  const targets = getTargets.all()

  console.log(`[스케줄러] 프로브 시작: ${targets.length}개 대상`)

  // 최대 10개씩 병렬 처리
  const CONCURRENCY = 10
  const results = []

  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const batch = targets.slice(i, i + CONCURRENCY)
    const batchResults = await Promise.all(
      batch.map(t => probeAndSave(t).then(r => ({ id: t.id, name: t.name, ...r })))
    )
    results.push(...batchResults)
  }

  // 7일 이상 된 데이터 정리
  const deleted = cleanup.run()

  const elapsed = Date.now() - start
  const upCount = results.filter(r => r.probe_success).length
  console.log(`[스케줄러] 완료: ${upCount}/${results.length} UP | ${elapsed}ms 소요 | ${deleted.changes}건 정리`)

  isRunning = false
  return { probed: results.length, up: upCount, down: results.length - upCount, elapsed_ms: elapsed, results }
}

// ─── cron 스케줄 등록 ─────────────────────────────────────────────
// 기본: 60초마다 실행 (환경변수로 조정 가능)
// CRON_SCHEDULE 예시:
//   "* * * * *"    = 1분마다
//   "*/2 * * * *"  = 2분마다
//   "*/5 * * * *"  = 5분마다
const CRON_SCHEDULE = process.env.CRON_SCHEDULE || '* * * * *'

let cronJob = null

function startScheduler() {
  if (cronJob) cronJob.stop()

  cronJob = cron.schedule(CRON_SCHEDULE, () => {
    probeAll().catch(err => console.error('[스케줄러 오류]', err))
  }, {
    scheduled: true,
    timezone: 'Asia/Seoul'
  })

  console.log(`[스케줄러] 시작 (스케줄: ${CRON_SCHEDULE})`)

  // 서버 시작 직후 1회 즉시 실행
  setTimeout(() => {
    probeAll().catch(err => console.error('[초기 프로브 오류]', err))
  }, 2000)
}

function stopScheduler() {
  if (cronJob) { cronJob.stop(); cronJob = null }
}

module.exports = { startScheduler, stopScheduler, probeAll, probeAndSave }
