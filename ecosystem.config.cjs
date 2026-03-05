// ecosystem.config.cjs — PM2 프로세스 설정
// FinMonitor: Node.js Express 서버 + Blackbox Exporter
module.exports = {
  apps: [
    // ─── FinMonitor 앱 서버 ────────────────────────────
    {
      name: 'finmonitor',
      script: 'src/server.js',
      cwd: '/home/user/webapp',
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
      error_file: '/home/user/webapp/logs/finmonitor-error.log',
      out_file: '/home/user/webapp/logs/finmonitor-out.log',
      merge_logs: true
    },

    // ─── Blackbox Exporter ────────────────────────────────
    {
      name: 'blackbox',
      script: '/home/user/webapp/blackbox/blackbox_exporter',
      args: '--config.file=/home/user/webapp/blackbox/blackbox.yml --web.listen-address=0.0.0.0:9115',
      cwd: '/home/user/webapp',
      instances: 1,
      exec_mode: 'fork',
      watch: false,
      interpreter: 'none',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      error_file: '/home/user/webapp/logs/blackbox-error.log',
      out_file: '/home/user/webapp/logs/blackbox-out.log',
      merge_logs: true
    }
  ]
}
