'use strict'

// 환경변수 로드 (.env 파일이 있으면 사용)
try {
  require('fs').readFileSync('.env', 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.split('=')
    if (k && v.length && !process.env[k.trim()]) {
      process.env[k.trim()] = v.join('=').trim()
    }
  })
} catch {}

const express  = require('express')
const path     = require('path')
const { startScheduler } = require('./scheduler')
const apiRoutes = require('./routes')
const asmRoutes = require('./asm-routes')
// ASM DB 초기화 (require 시점에 스키마+시드 실행)
require('./asm-db')

const app  = express()
const PORT = process.env.PORT || 3000

app.use(express.json())
app.use(express.urlencoded({ extended: false }))

// 정적 파일 (CSS, JS)
app.use('/static', express.static(path.join(__dirname, '../public/static')))

// API 라우터
app.use('/api', apiRoutes)
app.use('/api/asm', asmRoutes)

// SPA 진입점
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'))
})

// 서버 시작
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n========================================`)
  console.log(` FinMonitor 서버 시작`)
  console.log(` http://0.0.0.0:${PORT}`)
  console.log(`========================================`)
  console.log(` Blackbox URL : ${process.env.BLACKBOX_URL || 'http://localhost:9115'}`)
  console.log(` Cron         : ${process.env.CRON_SCHEDULE || '* * * * *'} (1분마다)`)
  console.log(` DB           : ${process.env.PGDATABASE || 'socopsasm'} (PostgreSQL)`)
  console.log(`========================================\n`)

  // 스케줄러 시작
  startScheduler()
})

module.exports = app
