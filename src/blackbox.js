'use strict'

/**
 * Blackbox Exporter /probe 엔드포인트를 직접 호출하고
 * Prometheus text format 메트릭을 파싱하여 구조화된 객체로 반환합니다.
 *
 * 호출 방식:
 *   GET http://<blackbox_host>:9115/probe?target=<url>&module=http_2xx
 *
 * 반환되는 Prometheus 텍스트 포맷 예시:
 *   probe_success 1
 *   probe_duration_seconds 0.123456
 *   probe_http_status_code 200
 *   probe_http_version 1.1
 *   probe_http_redirects 1
 *   probe_http_content_length 12345
 *   probe_http_duration_seconds{phase="resolve"}   0.001
 *   probe_http_duration_seconds{phase="connect"}   0.010
 *   probe_http_duration_seconds{phase="tls"}       0.045
 *   probe_http_duration_seconds{phase="processing"} 0.060
 *   probe_http_duration_seconds{phase="transfer"}  0.005
 *   probe_http_ssl 1
 *   probe_ssl_earliest_cert_expiry 1789000000   (Unix timestamp)
 *   probe_tls_version_info{version="TLS 1.3"} 1
 *   probe_dns_lookup_time_seconds 0.001234
 *   probe_failed_due_to_regex 0
 */

const axios = require('axios')

const BLACKBOX_URL   = process.env.BLACKBOX_URL   || 'http://localhost:9115'
const BLACKBOX_MODULE = process.env.BLACKBOX_MODULE || 'http_2xx'
const PROBE_TIMEOUT_MS = parseInt(process.env.PROBE_TIMEOUT_MS || '15000')

/**
 * Prometheus text 포맷 파서
 * 메트릭명, 라벨, 값을 추출합니다.
 */
function parsePrometheusText(text) {
  const metrics = {}
  const lines = text.split('\n')

  for (const raw of lines) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue

    // 라벨 있는 경우: metric_name{label="value",...} 숫자
    const labelMatch = line.match(/^(\w+)\{([^}]*)\}\s+([\S]+)$/)
    if (labelMatch) {
      const [, name, labelStr, value] = labelMatch
      if (!metrics[name]) metrics[name] = {}
      // 라벨 파싱
      const labels = {}
      for (const pair of labelStr.matchAll(/(\w+)="([^"]*)"/g)) {
        labels[pair[1]] = pair[2]
      }
      metrics[name][JSON.stringify(labels)] = { labels, value: parseFloat(value) }
      continue
    }

    // 라벨 없는 경우: metric_name 숫자
    const plainMatch = line.match(/^(\w+)\s+([\S]+)$/)
    if (plainMatch) {
      const [, name, value] = plainMatch
      metrics[name] = parseFloat(value)
    }
  }

  return metrics
}

/**
 * 단일 URL을 Blackbox Exporter로 프로브하고
 * 모든 메트릭을 포함한 결과 객체를 반환합니다.
 */
async function probe(targetUrl) {
  const probeStart = Date.now()

  try {
    const resp = await axios.get(`${BLACKBOX_URL}/probe`, {
      params: {
        target: targetUrl,
        module: BLACKBOX_MODULE,
        debug: 'false'
      },
      timeout: PROBE_TIMEOUT_MS,
      responseType: 'text',
      headers: { Accept: 'text/plain' }
    })

    const elapsed = Date.now() - probeStart
    const m = parsePrometheusText(resp.data)

    // ── probe_http_duration_seconds{phase=...} 파싱 ──────────────
    const dur = m['probe_http_duration_seconds'] || {}
    const phase = (p) => {
      const key = JSON.stringify({ phase: p })
      return dur[key] ? dur[key].value * 1000 : null   // ms 변환
    }

    // ── probe_tls_version_info{version=...} 파싱 ─────────────────
    let tls_version = null
    const tlsInfo = m['probe_tls_version_info']
    if (tlsInfo) {
      for (const entry of Object.values(tlsInfo)) {
        if (entry.value === 1 && entry.labels?.version) {
          tls_version = entry.labels.version
          break
        }
      }
    }

    // ── probe_tls_cipher_info{cipher=...} 파싱 ────────────────────
    let tls_cipher = null
    const cipherInfo = m['probe_tls_cipher_info']
    if (cipherInfo) {
      for (const entry of Object.values(cipherInfo)) {
        if (entry.value === 1 && entry.labels?.cipher_suite) {
          tls_cipher = entry.labels.cipher_suite
          break
        }
      }
    }

    // ── SSL 만료일 계산 ──────────────────────────────────────────
    let ssl_expiry_days = null
    let ssl_earliest_expiry = null
    const sslExpiry = m['probe_ssl_earliest_cert_expiry']
    if (typeof sslExpiry === 'number' && sslExpiry > 0) {
      const expiryMs = sslExpiry * 1000
      ssl_expiry_days = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24))
      ssl_earliest_expiry = new Date(expiryMs).toISOString().replace('T', ' ').substring(0, 19)
    }

    // ── http_version 파싱 ────────────────────────────────────────
    // probe_http_version_info{version="HTTP/2.0"} 1  또는 plain float
    let http_version = null
    const versionInfo = m['probe_http_version_info']
    if (versionInfo && typeof versionInfo === 'object') {
      for (const entry of Object.values(versionInfo)) {
        if (entry.value === 1 && entry.labels?.version) {
          http_version = entry.labels.version
          break
        }
      }
    } else if (typeof m['probe_http_version'] === 'number') {
      http_version = String(m['probe_http_version'])
    }

    return {
      ok: true,
      probe_success:    m['probe_success']        === 1,
      probe_failed:     m['probe_failed_due_to_regex'] === 1 ? 1 : 0,
      http_status_code: typeof m['probe_http_status_code']    === 'number' ? m['probe_http_status_code']    : null,
      http_version,
      http_redirects:   typeof m['probe_http_redirects']      === 'number' ? m['probe_http_redirects']      : null,
      http_content_length: typeof m['probe_http_content_length'] === 'number' ? m['probe_http_content_length'] : null,
      http_duration_resolve_ms:    phase('resolve'),
      http_duration_connect_ms:    phase('connect'),
      http_duration_tls_ms:        phase('tls'),
      http_duration_processing_ms: phase('processing'),
      http_duration_transfer_ms:   phase('transfer'),
      probe_duration_ms: typeof m['probe_duration_seconds'] === 'number'
        ? m['probe_duration_seconds'] * 1000
        : elapsed,
      tls_version,
      tls_cipher,
      ssl_expiry_days,
      ssl_earliest_expiry,
      dns_lookup_ms:    typeof m['probe_dns_lookup_time_seconds'] === 'number'
        ? m['probe_dns_lookup_time_seconds'] * 1000
        : null,
      http_ssl:         m['probe_http_ssl'] === 1,
      error_msg: null,
      raw_metrics: m   // 디버깅용 전체 메트릭 보존
    }

  } catch (err) {
    const elapsed = Date.now() - probeStart
    let error_msg = err.message

    // axios 에러 세분화
    if (err.code === 'ECONNREFUSED') {
      error_msg = `Blackbox Exporter 연결 실패 (${BLACKBOX_URL}). 실행 여부를 확인하세요.`
    } else if (err.code === 'ETIMEDOUT' || err.code === 'ECONNABORTED') {
      error_msg = `프로브 타임아웃 (${PROBE_TIMEOUT_MS}ms 초과)`
    }

    return {
      ok: false,
      probe_success:    false,
      probe_failed:     1,
      http_status_code: null,
      http_version:     null,
      http_redirects:   null,
      http_content_length: null,
      http_duration_resolve_ms:    null,
      http_duration_connect_ms:    null,
      http_duration_tls_ms:        null,
      http_duration_processing_ms: null,
      http_duration_transfer_ms:   null,
      probe_duration_ms: elapsed,
      tls_version:       null,
      tls_cipher:        null,
      ssl_expiry_days:   null,
      ssl_earliest_expiry: null,
      dns_lookup_ms:     null,
      http_ssl:          false,
      error_msg,
      raw_metrics: null
    }
  }
}

/**
 * Blackbox Exporter 자체 헬스체크
 */
async function checkBlackboxHealth() {
  try {
    const resp = await axios.get(`${BLACKBOX_URL}/-/healthy`, { timeout: 3000 })
    return { ok: true, status: resp.status }
  } catch (err) {
    return { ok: false, error: err.message }
  }
}

module.exports = { probe, checkBlackboxHealth, BLACKBOX_URL, BLACKBOX_MODULE }
