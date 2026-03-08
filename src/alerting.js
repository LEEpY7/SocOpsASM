'use strict'

const nodemailer = require('nodemailer')
const db         = require('./db')

/**
 * .env 또는 환경변수에서 Gmail SMTP 설정을 읽습니다.
 *   SMTP_HOST    기본값: smtp.gmail.com
 *   SMTP_PORT    기본값: 587
 *   SMTP_USER    발신 Gmail 주소
 *   SMTP_PASS    Gmail 앱 비밀번호 (2단계 인증 후 발급)
 *   SMTP_FROM    발신자 표시 이름 + 주소 (미설정 시 SMTP_USER 사용)
 */
function createTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    tls: { rejectUnauthorized: false }
  })
}

async function sendMail(to, subject, html) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('[알림] SMTP_USER / SMTP_PASS 미설정 → 메일 발송 건너뜀')
    return false
  }
  try {
    const transport = createTransport()
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to,
      subject,
      html
    })
    return true
  } catch (err) {
    console.error('[알림] 메일 발송 실패:', err.message)
    return false
  }
}

// ─── 알림 상태 관리 (중복 발송 방지) ────────────────────────────
const getAlertState  = db.prepare("SELECT * FROM alert_state WHERE module='availability' AND target_id = ?")
const upsertState    = db.prepare(`
  INSERT INTO alert_state (module, target_id, is_alerting, alerted_at)
  VALUES ('availability', @target_id, @is_alerting, @alerted_at)
  ON CONFLICT(module, target_id) DO UPDATE
    SET is_alerting = @is_alerting, alerted_at = @alerted_at
`)
const insertHistory  = db.prepare(`
  INSERT INTO alert_history (module, target_id, alert_config_id, alert_type, message, success)
  VALUES ('availability', @target_id, @alert_config_id, @alert_type, @message, @success)
`)

/**
 * 프로브 결과를 받아 필요 시 알림 발송
 * @param {object} target  - DB targets 레코드
 * @param {object} result  - blackbox.probe() 반환값
 */
async function processAlert(target, result) {
  const configs = db.prepare(
    'SELECT * FROM alert_configs WHERE enabled = 1'
  ).all()
  if (configs.length === 0) return

  const state = getAlertState.get(target.id) || { is_alerting: 0 }
  const isDown = !result.probe_success

  for (const cfg of configs) {
    // ── DOWN 알림 ──────────────────────────────────────────────
    if (cfg.down_notify && isDown && !state.is_alerting) {
      const subject = `🚨 [장애] ${target.name} 접속 불가`
      const html = buildDownHtml(target, result)
      const ok = await sendMail(cfg.to_email, subject, html)

      insertHistory.run({
        target_id: target.id,
        alert_config_id: cfg.id,
        alert_type: 'down',
        message: `DOWN: ${target.name} (${target.url})`,
        success: ok ? 1 : 0
      })

      console.log(`[알림] DOWN 메일 → ${cfg.to_email} | ${target.name} | 성공: ${ok}`)
    }

    // ── 복구 알림 ──────────────────────────────────────────────
    if (!isDown && state.is_alerting) {
      const subject = `✅ [복구] ${target.name} 정상 복구`
      const html = buildRecoveryHtml(target, result)
      const ok = await sendMail(cfg.to_email, subject, html)

      insertHistory.run({
        target_id: target.id,
        alert_config_id: cfg.id,
        alert_type: 'recovery',
        message: `RECOVERY: ${target.name}`,
        success: ok ? 1 : 0
      })

      console.log(`[알림] RECOVERY 메일 → ${cfg.to_email} | ${target.name} | 성공: ${ok}`)
    }

    // ── 응답 느림 알림 (UP이지만 임계값 초과, 알림 상태 아닐 때) ──
    if (!isDown && !state.is_alerting && cfg.threshold_ms > 0) {
      const respMs = result.probe_duration_ms
      if (respMs && respMs > cfg.threshold_ms) {
        const subject = `⚠️ [응답지연] ${target.name} 응답시간 ${Math.round(respMs)}ms`
        const html = buildSlowHtml(target, result, cfg.threshold_ms)
        const ok = await sendMail(cfg.to_email, subject, html)

        insertHistory.run({
          target_id: target.id,
          alert_config_id: cfg.id,
          alert_type: 'slow',
          message: `SLOW: ${target.name} ${Math.round(respMs)}ms > ${cfg.threshold_ms}ms`,
          success: ok ? 1 : 0
        })
      }
    }

    // ── SSL 만료 임박 알림 ─────────────────────────────────────
    if (cfg.ssl_warn_days > 0 && result.ssl_expiry_days !== null) {
      if (result.ssl_expiry_days <= cfg.ssl_warn_days && result.ssl_expiry_days >= 0) {
        const subject = `🔐 [SSL 만료임박] ${target.name} ${result.ssl_expiry_days}일 남음`
        const html = buildSslHtml(target, result)
        const ok = await sendMail(cfg.to_email, subject, html)

        insertHistory.run({
          target_id: target.id,
          alert_config_id: cfg.id,
          alert_type: 'ssl_expiry',
          message: `SSL: ${target.name} ${result.ssl_expiry_days}일`,
          success: ok ? 1 : 0
        })
      }
    }
  }

  // 알림 상태 업데이트
  upsertState.run({
    target_id:   target.id,
    is_alerting: isDown ? 1 : 0,
    alerted_at:  new Date().toISOString()
  })
}

// ─── HTML 템플릿 ────────────────────────────────────────────────
const style = `
  body { font-family: 'Noto Sans KR', sans-serif; background: #f1f5f9; margin: 0; padding: 20px; }
  .card { background: white; border-radius: 10px; padding: 24px; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
  .header { padding: 16px 24px; border-radius: 8px; margin-bottom: 20px; }
  .header.down { background: #fef2f2; border-left: 4px solid #ef4444; }
  .header.recovery { background: #f0fdf4; border-left: 4px solid #22c55e; }
  .header.slow { background: #fefce8; border-left: 4px solid #eab308; }
  .header.ssl { background: #eff6ff; border-left: 4px solid #3b82f6; }
  h2 { margin: 0 0 6px; font-size: 18px; }
  .meta { font-size: 12px; color: #94a3b8; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: #f8fafc; color: #64748b; font-weight: 600; border-bottom: 1px solid #e2e8f0; }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; color: #334155; }
  .footer { margin-top: 20px; font-size: 11px; color: #94a3b8; text-align: center; }
`

function buildDownHtml(target, result) {
  return `<html><head><style>${style}</style></head><body>
    <div class="card">
      <div class="header down">
        <h2>🚨 가용성 장애 감지</h2>
        <div class="meta">${new Date().toLocaleString('ko-KR')} 감지</div>
      </div>
      <table>
        <tr><th>대상</th><td><b>${target.name}</b></td></tr>
        <tr><th>URL</th><td>${target.url}</td></tr>
        <tr><th>카테고리</th><td>${target.category} / ${target.sub_category || '-'}</td></tr>
        <tr><th>HTTP 상태</th><td>${result.http_status_code || 'N/A'}</td></tr>
        <tr><th>응답시간</th><td>${result.probe_duration_ms ? Math.round(result.probe_duration_ms) + 'ms' : '-'}</td></tr>
        <tr><th>오류 내용</th><td style="color:#ef4444">${result.error_msg || '-'}</td></tr>
      </table>
      <div class="footer">FinMonitor - 금융권 웹 가용성 모니터링</div>
    </div>
  </body></html>`
}

function buildRecoveryHtml(target, result) {
  return `<html><head><style>${style}</style></head><body>
    <div class="card">
      <div class="header recovery">
        <h2>✅ 서비스 정상 복구</h2>
        <div class="meta">${new Date().toLocaleString('ko-KR')} 복구 확인</div>
      </div>
      <table>
        <tr><th>대상</th><td><b>${target.name}</b></td></tr>
        <tr><th>URL</th><td>${target.url}</td></tr>
        <tr><th>HTTP 상태</th><td style="color:#22c55e">${result.http_status_code || '-'}</td></tr>
        <tr><th>응답시간</th><td>${result.probe_duration_ms ? Math.round(result.probe_duration_ms) + 'ms' : '-'}</td></tr>
        <tr><th>TLS</th><td>${result.tls_version || '-'}</td></tr>
      </table>
      <div class="footer">FinMonitor - 금융권 웹 가용성 모니터링</div>
    </div>
  </body></html>`
}

function buildSlowHtml(target, result, threshold) {
  return `<html><head><style>${style}</style></head><body>
    <div class="card">
      <div class="header slow">
        <h2>⚠️ 응답시간 임계값 초과</h2>
        <div class="meta">${new Date().toLocaleString('ko-KR')}</div>
      </div>
      <table>
        <tr><th>대상</th><td><b>${target.name}</b></td></tr>
        <tr><th>URL</th><td>${target.url}</td></tr>
        <tr><th>응답시간</th><td style="color:#eab308"><b>${Math.round(result.probe_duration_ms)}ms</b></td></tr>
        <tr><th>임계값</th><td>${threshold}ms</td></tr>
        <tr><th>DNS</th><td>${result.dns_lookup_ms ? Math.round(result.dns_lookup_ms) + 'ms' : '-'}</td></tr>
        <tr><th>TLS 연결</th><td>${result.http_duration_tls_ms ? Math.round(result.http_duration_tls_ms) + 'ms' : '-'}</td></tr>
        <tr><th>서버 처리</th><td>${result.http_duration_processing_ms ? Math.round(result.http_duration_processing_ms) + 'ms' : '-'}</td></tr>
      </table>
      <div class="footer">FinMonitor - 금융권 웹 가용성 모니터링</div>
    </div>
  </body></html>`
}

function buildSslHtml(target, result) {
  return `<html><head><style>${style}</style></head><body>
    <div class="card">
      <div class="header ssl">
        <h2>🔐 SSL 인증서 만료 임박</h2>
        <div class="meta">${new Date().toLocaleString('ko-KR')}</div>
      </div>
      <table>
        <tr><th>대상</th><td><b>${target.name}</b></td></tr>
        <tr><th>URL</th><td>${target.url}</td></tr>
        <tr><th>만료까지</th><td style="color:#ef4444"><b>${result.ssl_expiry_days}일</b></td></tr>
        <tr><th>만료 일시</th><td>${result.ssl_earliest_expiry || '-'}</td></tr>
        <tr><th>TLS 버전</th><td>${result.tls_version || '-'}</td></tr>
        <tr><th>암호화 스위트</th><td style="font-size:11px">${result.tls_cipher || '-'}</td></tr>
      </table>
      <div class="footer">FinMonitor - 금융권 웹 가용성 모니터링</div>
    </div>
  </body></html>`
}

module.exports = { processAlert, sendMail }
