'use strict'

const express  = require('express')
const path     = require('path')
const fs       = require('fs')
loadEnvFile()

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

function loadEnvFile() {
  const envPath = path.join(__dirname, '../.env')
  if (!fs.existsSync(envPath)) return

  const contents = fs.readFileSync(envPath, 'utf8')
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue

    const eqIdx = line.indexOf('=')
    if (eqIdx <= 0) continue

    const key = line.slice(0, eqIdx).trim()
    if (!key || process.env[key]) continue

    let value = line.slice(eqIdx + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    process.env[key] = value
  }
}
