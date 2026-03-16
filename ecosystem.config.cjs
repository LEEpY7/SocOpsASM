// ecosystem.config.cjs — PM2 프로세스 설정
// FinMonitor: Node.js Express 서버 + Blackbox Exporter
const path = require('path')
const fs = require('fs')

const APP_ROOT = path.resolve(__dirname)
const LOG_DIR = path.join(APP_ROOT, 'logs')
const BLACKBOX_BIN = path.join(APP_ROOT, 'blackbox', 'blackbox_exporter')
const BLACKBOX_CONFIG = path.join(APP_ROOT, 'blackbox', 'blackbox.yml')

// 어떤 위치로 프로젝트를 옮겨도 PM2가 실행 가능하도록 런타임에 로그 디렉터리 보장
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true })
}

module.exports = {
  apps: [
    // ─── FinMonitor 앱 서버 ────────────────────────────
    {
      name: 'finmonitor',
      script: 'src/server.js',
      cwd: APP_ROOT,
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      env: {
        NODE_ENV: 'development',
        PORT: 3000,
        // Blackbox Exporter 주소 (아래 blackbox 프로세스와 연동)
        BLACKBOX_URL: 'http://localhost:9115',
        BLACKBOX_MODULE: 'http_2xx',
        PROBE_TIMEOUT_MS: '15000',
        // 점검 스케줄 (기본: 1분마다)
        CRON_SCHEDULE: '* * * * *',
        // Gmail SMTP — 실제 사용 시 .env 파일에 설정
        // SMTP_USER: 'your-email@gmail.com',
        // SMTP_PASS: 'xxxx-xxxx-xxxx-xxxx',
        // SMTP_FROM: 'FinMonitor <your-email@gmail.com>'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      error_file: path.join(LOG_DIR, 'finmonitor-error.log'),
      out_file: path.join(LOG_DIR, 'finmonitor-out.log'),
      merge_logs: true
    },

    // ─── Blackbox Exporter ────────────────────────────────
    {
      name: 'blackbox',
      script: BLACKBOX_BIN,
      args: `--config.file=${BLACKBOX_CONFIG} --web.listen-address=0.0.0.0:9115`,
      cwd: APP_ROOT,
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      interpreter: 'none',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      error_file: path.join(LOG_DIR, 'blackbox-error.log'),
      out_file: path.join(LOG_DIR, 'blackbox-out.log'),
      merge_logs: true
    }
  ]
}
