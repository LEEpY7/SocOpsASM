'use strict'
/**
 * ASM 스캔 파이프라인 엔진
 * 
 * 파이프라인 순서:
 *   1. Amass     — 패시브 서브도메인 열거
 *   2. Subfinder — 서브도메인 열거 (보조)
 *   3. dnsx      — DNS 확인 (FQDN → IP 매핑)
 *   4. Naabu     — 빠른 포트 스캔
 *   5. Masscan   — 대규모 포트 스캔 (IP 대역 대상)
 *   6. Nmap      — 서비스/버전 탐지
 *   7. httpx     — 웹 배너/기술스택 식별
 *   8. Nuclei    — 취약점 스캔
 * 
 * 각 단계 결과 → Raw Zone 저장 → Normalized Zone 파싱 적용
 */

const { spawn }  = require('child_process')
const path        = require('path')
const fs          = require('fs')
const os          = require('os')
const { asmDb, refreshAssetCurrent } = require('./asm-db')

// ─────────────────────────────────────────────────────────────
//  툴 경로 설정
//
//  우선순위:
//    1) 프로젝트 루트의 tools/ 디렉토리 (로컬 배포용)
//       예: <project>/tools/amass
//    2) 시스템 PATH (개발 환경 / 서버에 직접 설치된 경우)
//
//  로컬 배포 시 tools/ 에 바이너리를 넣으면 자동으로 우선 사용됩니다.
//  ※ httpx 는 반드시 ProjectDiscovery httpx (Go 바이너리) 를 사용해야 합니다.
//     Python httpx 클라이언트와 이름이 같으므로 tools/httpx 에 PD 버전을 배치하세요.
// ─────────────────────────────────────────────────────────────
const TOOLS_DIR = process.env.ASM_TOOLS_DIR || path.join(__dirname, '../tools')

function toolPath(name) {
  // 1순위: tools/ 디렉토리
  const local = path.join(TOOLS_DIR, name)
  if (fs.existsSync(local)) return local
  // 2순위: 시스템 PATH (which 없이 이름만 반환 → spawn이 PATH 탐색)
  return name
}

// 각 툴 실행 경로 (런타임에 결정)
const TOOLS = {
  amass:     () => toolPath('amass'),
  subfinder: () => toolPath('subfinder'),
  dnsx:      () => toolPath('dnsx'),
  naabu:     () => toolPath('naabu'),
  masscan:   () => toolPath('masscan'),
  nmap:      () => toolPath('nmap'),
  // httpx: ProjectDiscovery httpx만 사용 (Python httpx와 충돌 방지)
  // tools/httpx 가 없으면 시스템에서 pd-httpx 또는 httpx를 찾아 사용
  httpx:     () => {
    const local = path.join(TOOLS_DIR, 'httpx')
    if (fs.existsSync(local)) return local
    // 시스템에 설치된 PD httpx 확인: pd-httpx 별칭 또는 일반 httpx
    const candidates = [
      '/usr/local/bin/pd-httpx',
      path.join(os.homedir(), 'go/bin/httpx'),
      '/root/go/bin/httpx',
      '/usr/local/bin/httpx',   // 마지막 수단 (PD 버전이길 기대)
    ]
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        // Python 스크립트인지 확인 (첫 줄이 #!/...python)
        try {
          const first = fs.readFileSync(c, 'utf8').slice(0, 30)
          if (first.includes('python')) continue  // Python httpx 스킵
        } catch (_) {}
        return c
      }
    }
    return 'httpx'  // fallback
  },
  nuclei:    () => toolPath('nuclei'),
}

// 실행 전 툴 존재 여부 검증
function validateTools() {
  const missing = []
  for (const [name, pathFn] of Object.entries(TOOLS)) {
    const p = pathFn()
    const exists = p !== name && fs.existsSync(p)
    if (!exists && p === name) {
      // 시스템 PATH 에서도 체크 (which 대신 직접 실행 시도)
      // 여기서는 경고만 기록 (실제 실행 시 오류 발생)
    }
    console.log(`[TOOLS] ${name.padEnd(10)} → ${p}  ${exists ? '✓' : '(시스템 PATH)'}`)
  }
  return missing
}

// 임시 작업 디렉토리
const TMP_DIR = path.join(os.tmpdir(), 'asm-pipeline')
if (!fs.existsSync(TMP_DIR)) fs.mkdirSync(TMP_DIR, { recursive: true })

// 현재 실행 중인 파이프라인 맵 { runId → { proc, cancelled } }
const activeRuns = new Map()

// ─────────────────────────────────────────────────────────────
//  유틸
// ─────────────────────────────────────────────────────────────
function now() { return new Date().toISOString().replace('T',' ').slice(0,19) }

function log(runId, stage, msg) {
  console.log(`[PIPELINE run=${runId} stage=${stage}] ${msg}`)
}

/** scan_target 전체 활성 목록 */
function getActiveTargets() {
  return asmDb.prepare(`
    SELECT id, type, value, label FROM scan_target WHERE enabled=1
  `).all()
}

/** IP 대역 목록만 */
function getIpRangeTargets() {
  return asmDb.prepare(`
    SELECT value FROM scan_target WHERE type='ip_range' AND enabled=1
  `).all().map(r => r.value)
}

/** 도메인 목록만 */
function getDomainTargets() {
  return asmDb.prepare(`
    SELECT value FROM scan_target WHERE type='domain' AND enabled=1
  `).all().map(r => r.value)
}

/** pipeline_stage_log 업데이트 */
function updateStage(stageRowId, fields) {
  const sets = Object.keys(fields).map(k => `${k}=@${k}`).join(',')
  asmDb.prepare(`UPDATE pipeline_stage_log SET ${sets} WHERE id=@id`)
       .run({ ...fields, id: stageRowId })
}

/** pipeline_run 업데이트 */
function updateRun(runId, fields) {
  const sets = Object.keys(fields).map(k => `${k}=@${k}`).join(',')
  asmDb.prepare(`UPDATE pipeline_run SET ${sets} WHERE id=@id`)
       .run({ ...fields, id: runId })
}

/** 단계 로그 생성 */
function createStageLog(runId, stage) {
  const res = asmDb.prepare(`
    INSERT INTO pipeline_stage_log (run_id, stage, status)
    VALUES (@runId, @stage, 'pending')
    RETURNING id
  `).run({ runId, stage })
  return res.lastInsertRowid
}

/** 임시 파일 경로 */
function tmpFile(runId, name) {
  return path.join(TMP_DIR, `run${runId}_${name}`)
}

/** 취소 여부 확인 */
function isCancelled(runId) {
  const r = activeRuns.get(runId)
  if (r && r.cancelled) return true
  const dbRun = asmDb.prepare('SELECT cancel_requested, status FROM pipeline_run WHERE id=?').get(runId)
  return !!(dbRun && (Number(dbRun.cancel_requested) === 1 || dbRun.status === 'cancelled'))
}

// ─────────────────────────────────────────────────────────────
//  명령 실행 헬퍼
// ─────────────────────────────────────────────────────────────
function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const timeout = opts.timeout || 300000  // 기본 5분
    let stdout = '', stderr = ''
    const child = spawn(cmd, args, { timeout })
    const runState = opts.runId ? activeRuns.get(opts.runId) : null
    if (runState) runState.currentChild = child
    child.stdout.on('data', d => { stdout += d.toString() })
    child.stderr.on('data', d => { stderr += d.toString() })
    child.on('close', code => {
      if (runState && runState.currentChild === child) runState.currentChild = null
      resolve({ code, stdout, stderr })
    })
    child.on('error', err => {
      if (runState && runState.currentChild === child) runState.currentChild = null
      if (err && err.code === 'EACCES') {
        return reject(new Error(`툴 실행 권한이 없습니다: ${cmd} (chmod +x ${cmd} 또는 ASM_TOOLS_DIR 경로 확인)`))
      }
      if (err && err.code === 'ENOENT') {
        return reject(new Error(`툴을 찾을 수 없습니다: ${cmd} (ASM_TOOLS_DIR 또는 시스템 PATH 확인)`))
      }
      reject(err)
    })
  })
}

// ─────────────────────────────────────────────────────────────
//  단계 1: Amass — 패시브 서브도메인 열거
// ─────────────────────────────────────────────────────────────
async function runAmass(runId, stageId, domains) {
  if (!domains.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'도메인 대상 없음' })
    return []
  }

  const outFile = tmpFile(runId, 'amass.txt')
  const AMASS = TOOLS.amass()
  const args = ['enum', '-passive', '-d', domains.join(','), '-o', outFile, '-silent']
  const cmdLine = `${AMASS} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'amass', `실행: ${cmdLine}`)

  let result
  try {
    result = await runCmd(AMASS, args, { timeout: 180000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return []
  }

  // 결과 파싱
  const fqdns = []
  if (fs.existsSync(outFile)) {
    const lines = fs.readFileSync(outFile, 'utf8').trim().split('\n').filter(Boolean)
    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('amass-run'||@runId, 'amass', @scope, 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, scope: domains.join(','), s: now(), f: now(), cnt: lines.length })

    const ins = asmDb.prepare(`
      INSERT INTO raw_amass (job_id, fqdn, root_domain, source, raw_json)
      VALUES (@jobId, @fqdn, @root, 'amass', @raw)
    `)
    const tx = asmDb.transaction(rows => rows.forEach(r => ins.run(r)))
    const rows = lines.map(line => ({
      jobId: jobRes.lastInsertRowid,
      fqdn:  line.trim(),
      root:  line.trim().split('.').slice(-2).join('.'),
      raw:   JSON.stringify({ line })
    }))
    tx(rows)
    fqdns.push(...lines.map(l => l.trim()).filter(Boolean))
    updateStage(stageId, { status:'done', finished_at: now(), result_count: lines.length, stdout_tail: lines.slice(-5).join('\n') })
    log(runId, 'amass', `완료: ${lines.length}개 FQDN 발견`)
  } else {
    // 출력 파일이 없으면 stderr에서 파싱 시도
    updateStage(stageId, { status:'done', finished_at: now(), result_count:0, stdout_tail: result.stderr.slice(-200) })
  }

  return [...new Set(fqdns)]
}

// ─────────────────────────────────────────────────────────────
//  단계 2: Subfinder — 서브도메인 열거
// ─────────────────────────────────────────────────────────────
async function runSubfinder(runId, stageId, domains) {
  if (!domains.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'도메인 대상 없음' })
    return []
  }

  const SUBFINDER = TOOLS.subfinder()
  const domainArgs = domains.flatMap(d => ['-d', d])
  const args = [...domainArgs, '-silent', '-all']
  const cmdLine = `${SUBFINDER} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'subfinder', `실행: ${cmdLine}`)

  let result
  try {
    result = await runCmd(SUBFINDER, args, { timeout: 120000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return []
  }

  const fqdns = result.stdout.trim().split('\n').filter(Boolean).map(l => l.trim())

  if (fqdns.length > 0) {
    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('subfinder-run'||@runId, 'subfinder', @scope, 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, scope: domains.join(','), s: now(), f: now(), cnt: fqdns.length })

    const ins = asmDb.prepare(`
      INSERT INTO raw_subfinder (job_id, fqdn, root_domain, source, raw_line)
      VALUES (@jobId, @fqdn, @root, 'subfinder', @raw)
    `)
    const tx = asmDb.transaction(rows => rows.forEach(r => ins.run(r)))
    tx(fqdns.map(fqdn => ({
      jobId: jobRes.lastInsertRowid,
      fqdn,
      root: fqdn.split('.').slice(-2).join('.'),
      raw: fqdn
    })))
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: fqdns.length, stdout_tail: fqdns.slice(-5).join('\n') })
  log(runId, 'subfinder', `완료: ${fqdns.length}개 FQDN 발견`)
  return fqdns
}

// ─────────────────────────────────────────────────────────────
//  단계 3: dnsx — DNS 확인 (FQDN → IP)
// ─────────────────────────────────────────────────────────────
async function runDnsx(runId, stageId, allFqdns) {
  if (!allFqdns.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'FQDN 없음' })
    return { fqdnIpMap: {}, ips: [] }
  }

  const inFile  = tmpFile(runId, 'dnsx_input.txt')
  fs.writeFileSync(inFile, [...new Set(allFqdns)].join('\n'))

  // dnsx는 -o 파일 출력이 동작하지 않는 버전이 있으므로 stdout 직접 캡처
  const DNSX = TOOLS.dnsx()
  const args = ['-l', inFile, '-a', '-resp', '-json', '-silent', '-retry', '2']
  const cmdLine = `${DNSX} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'dnsx', `실행: ${cmdLine} (${allFqdns.length}개 FQDN)`)

  let result
  try {
    result = await runCmd(DNSX, args, { timeout: 120000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return { fqdnIpMap: {}, ips: [] }
  }

  const fqdnIpMap = {}
  const ipSet = new Set()
  let count = 0

  const lines = result.stdout.trim().split('\n').filter(Boolean)
  const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('dnsx-run'||@runId, 'dnsx', 'fqdns', 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, s: now(), f: now(), cnt: lines.length })

  const ins = asmDb.prepare(`
      INSERT INTO raw_dnsx (job_id, fqdn, record_type, answer, status_code, raw_json)
      VALUES (@jobId, @fqdn, @rtype, @answer, @status, @raw)
    `)
  const tx = asmDb.transaction(rows => rows.forEach(r => ins.run(r)))
  const rows = []

  for (const line of lines) {
    try {
      const obj = JSON.parse(line)
      const fqdn = obj.host || obj.name || ''
      const ips2  = obj.a || []
      const rtype = 'A'
      for (const ip of ips2) {
        rows.push({ jobId: jobRes.lastInsertRowid, fqdn, rtype, answer: ip, status: 'NOERROR', raw: line })
        if (!fqdnIpMap[fqdn]) fqdnIpMap[fqdn] = []
        fqdnIpMap[fqdn].push(ip)
        ipSet.add(ip)
      }
      count++
    } catch(_) {}
  }
  tx(rows)

  const ips = [...ipSet]
  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'dnsx', `완료: IP ${ips.length}개, 매핑 ${Object.keys(fqdnIpMap).length}개`)
  return { fqdnIpMap, ips }
}

// ─────────────────────────────────────────────────────────────
//  단계 4: Naabu — top-1000 포트 스캔 (도메인 계열 IP 전용)
//
//  역할 분리 원칙:
//    • Naabu  → dnsx가 확인한 IP (FQDN 기반 자산) top-1000 포트
//    • Masscan → scan_target에 직접 입력된 CIDR 전체 포트 (1-65535)
//  → ipRanges는 절대 Naabu에 넣지 않는다 (Masscan이 담당)
// ─────────────────────────────────────────────────────────────
async function runNaabu(runId, stageId, discoveredIps) {
  // discoveredIps: dnsx 단계에서 FQDN → IP 매핑으로 얻은 IP 목록만 사용
  const targets = [...new Set(discoveredIps)]
  if (!targets.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'dnsx 발견 IP 없음 (도메인 대상 없음)' })
    return {}
  }

  const inFile  = tmpFile(runId, 'naabu_input.txt')
  const outFile = tmpFile(runId, 'naabu_output.txt')
  fs.writeFileSync(inFile, targets.join('\n'))

  // top-1000 서비스 포트 + 주요 웹/DB 포트
  const NAABU = TOOLS.naabu()
  const topPorts = 'top-1000'
  const args = ['-l', inFile, '-top-ports', topPorts, '-o', outFile, '-silent', '-rate', '1000', '-timeout', '3']
  const cmdLine = `${NAABU} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'naabu', `실행: ${cmdLine} (dnsx 발견 IP ${targets.length}개 대상, top-1000 포트)`)

  try {
    await runCmd(NAABU, args, { timeout: 300000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return {}
  }

  const portMap = {}  // { ip: [ports...] }
  let count = 0

  if (fs.existsSync(outFile)) {
    const lines = fs.readFileSync(outFile, 'utf8').trim().split('\n').filter(Boolean)
    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('naabu-run'||@runId, 'naabu', @scope, 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, scope: allTargets.slice(0,3).join(','), s: now(), f: now(), cnt: lines.length })

    const ins = asmDb.prepare(`
      INSERT INTO raw_naabu (job_id, ip, port, protocol, raw_line)
      VALUES (@jobId, @ip, @port, 'tcp', @raw)
    `)
    const tx = asmDb.transaction(rows => rows.forEach(r => ins.run(r)))
    const rows = []

    for (const line of lines) {
      // naabu 출력: ip:port
      const m = line.match(/^(.+):(\d+)$/)
      if (m) {
        const [, ip, portStr] = m
        const port = parseInt(portStr)
        rows.push({ jobId: jobRes.lastInsertRowid, ip, port, raw: line })
        if (!portMap[ip]) portMap[ip] = []
        portMap[ip].push(port)
        count++
      }
    }
    tx(rows)
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'naabu', `완료: ${count}개 오픈 포트 (top-1000, FQDN 계열 IP ${targets.length}개)`)
  return portMap
}

// ─────────────────────────────────────────────────────────────
//  단계 5: Masscan — 전체 포트 스캔 (모든 확인된 자산 대상)
//
//  역할 분리 원칙:
//    ▶ Naabu  : discoveredIps (FQDN→dnsx IP) → top-1000 포트 빠른 확인
//    ▶ Masscan: discoveredIps + ipRanges 전체 자산 → 1-65535 전체 포트
//
//  입력 우선순위:
//    1) discoveredIps: 도메인 계열에서 dnsx가 확인한 IP (단일 IP)
//    2) ipRanges:      scan_target에 등록된 CIDR 대역
//    → 둘 다 없으면 skip
//
//  주의: Masscan은 raw socket SYN 방식 → root 권한 필요
//        권한 부족 시 graceful skip (Naabu top-1000으로 대체)
// ─────────────────────────────────────────────────────────────
async function runMasscan(runId, stageId, discoveredIps, ipRanges) {
  // 단일 IP(dnsx 결과) + CIDR 대역(scan_target) 합산
  const allTargets = [...new Set(discoveredIps), ...ipRanges]
  if (!allTargets.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0,
      error_msg:'스캔 대상 없음 (discoveredIps + ipRanges 모두 비어있음)' })
    log(runId, 'masscan', '대상 없음 → skip')
    return {}
  }

  const outFile = tmpFile(runId, 'masscan_output.json')
  const MASSCAN = TOOLS.masscan()
  // 전체 포트 1-65535 스캔 (rate는 /24 기준 약 2-3분)
  const args = [...allTargets, '-p', '1-65535', '--rate', '10000', '-oJ', outFile, '--open-only']
  const cmdLine = `${MASSCAN} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'masscan', `실행: ${cmdLine} (단일IP ${discoveredIps.length}개 + CIDR ${ipRanges.length}개, 전체포트 1-65535)`)

  let result
  try {
    result = await runCmd(MASSCAN, args, { timeout: 300000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return {}
  }

  const portMap = {}
  let count = 0

  // root 권한 부족 시 graceful skip
  if (result.code !== 0 && (result.stderr.includes('permission') || result.stderr.includes('FATAL') || result.stderr.includes('Operation not permitted'))) {
    updateStage(stageId, { status:'skipped', finished_at: now(),
      error_msg:'root 권한 필요 — Masscan은 raw socket(SYN) 방식으로 root 필요. Naabu top-1000 결과를 사용합니다.' })
    log(runId, 'masscan', '권한 부족 → skip (Naabu 결과로 대체)')
    return {}
  }

  if (fs.existsSync(outFile)) {
    try {
      // masscan JSON 포맷: [{ ip, ports:[{port,proto,status}] }]
      let raw = fs.readFileSync(outFile, 'utf8').trim()
      if (raw.endsWith(',')) raw = raw.slice(0,-1)  // trailing comma 제거
      if (!raw.startsWith('[')) raw = '[' + raw + ']'
      const records = JSON.parse(raw)

      const jobRes = asmDb.prepare(`
        INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
        VALUES ('masscan-run'||@runId, 'masscan', @scope, 'done', @s, @f, @cnt)
        RETURNING id
      `).run({ runId, scope: allTargets.slice(0,5).join(','), s: now(), f: now(), cnt: records.length })

      const ins = asmDb.prepare(`
        INSERT INTO raw_masscan (job_id, ip, port, protocol, raw_json)
        VALUES (@jobId, @ip, @port, @proto, @raw)
      `)
      const tx = asmDb.transaction(rows => rows.forEach(r => ins.run(r)))
      const rows = []

      for (const rec of records) {
        const ip = rec.ip
        for (const p of (rec.ports || [])) {
          rows.push({ jobId: jobRes.lastInsertRowid, ip, port: p.port, proto: p.proto, raw: JSON.stringify(rec) })
          if (!portMap[ip]) portMap[ip] = []
          portMap[ip].push(p.port)
          count++
        }
      }
      tx(rows)
    } catch(e) {
      log(runId, 'masscan', `JSON 파싱 실패: ${e.message}`)
    }
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'masscan', `완료: ${count}개 오픈 포트 (단일IP ${discoveredIps.length}개 + CIDR ${ipRanges.length}개 대역, 전체포트 1-65535)`)
  return portMap
}

// ─────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────
//  단계 6: Nmap — 서비스/버전 탐지
//
//  입력 병합 전략:
//    Naabu  포트맵 (top-1000, FQDN 계열 IP)
//  + Masscan 포트맵 (1-65535, CIDR 대역 IP)
//  → 합집합으로 Nmap 스캔 대상 결정
//  → Masscan이 skip된 경우 Naabu 결과만 사용 (정상 동작)
// ─────────────────────────────────────────────────────────────
async function runNmap(runId, stageId, naabuPortMap, masscanPortMap) {
  // Naabu(top-1000) + Masscan(전체포트) 결과 병합
  // 같은 IP라면 두 결과의 포트 합집합으로 Nmap 스캔
  const mergedPortMap = { ...naabuPortMap }
  for (const [ip, ports] of Object.entries(masscanPortMap)) {
    if (!mergedPortMap[ip]) mergedPortMap[ip] = []
    mergedPortMap[ip] = [...new Set([...mergedPortMap[ip], ...ports])]
  }

  const ipsWithPorts = Object.entries(mergedPortMap).filter(([, p]) => p.length > 0)
  if (!ipsWithPorts.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'포트 데이터 없음' })
    return {}
  }

  const outFile = tmpFile(runId, 'nmap_output.xml')
  // IP 목록과 포트를 모아서 배치 스캔
  const ips   = ipsWithPorts.map(([ip]) => ip)
  const ports = [...new Set(ipsWithPorts.flatMap(([, p]) => p))].join(',')

  const NMAP = TOOLS.nmap()
  const args = ['-sV', '-sC', '--open', '-p', ports, '-oX', outFile, '--host-timeout', '30s', '-T4', ...ips]
  const cmdLine = `${NMAP} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'nmap', `실행: ${cmdLine} (${ips.length}개 IP)`)

  let result
  try {
    result = await runCmd(NMAP, args, { timeout: 600000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return {}
  }

  // XML 파싱 → raw_nmap 저장 + normalized network_service 저장
  const serviceMap = {}  // { ip: [{ port, proto, state, service, product, version }] }
  let count = 0

  if (fs.existsSync(outFile)) {
    const xml = fs.readFileSync(outFile, 'utf8')
    // 간단한 XML 파싱 (xml2js 없이)
    const hostBlocks = xml.match(/<host[\s\S]*?<\/host>/g) || []

    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('nmap-run'||@runId, 'nmap', @scope, 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, scope: ips.slice(0,3).join(','), s: now(), f: now(), cnt: hostBlocks.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_nmap (job_id, ip, port, protocol, state, service_name, product, version, extra_info, os_name, cpe, script_output, raw_xml)
      VALUES (@jobId, @ip, @port, @proto, @state, @svc, @prod, @ver, @extra, @os, @cpe, @script, @raw)
    `)
    const svcIns = asmDb.prepare(`
      INSERT INTO network_service (asset_id, ip, port, protocol, state, service_name, product, version, banner, extra_info, fingerprint_source, first_seen, last_seen)
      SELECT a.id, @ip, @port, @proto, @state, @svc, @prod, @ver, @banner, @extra, 'nmap', @now, @now
      FROM asset a WHERE a.ip=@ip
      ON CONFLICT (ip, port, protocol) DO UPDATE SET
        state=EXCLUDED.state,
        service_name=COALESCE(EXCLUDED.service_name, network_service.service_name),
        product=COALESCE(EXCLUDED.product, network_service.product),
        version=COALESCE(EXCLUDED.version, network_service.version),
        banner=COALESCE(EXCLUDED.banner, network_service.banner),
        extra_info=COALESCE(EXCLUDED.extra_info, network_service.extra_info),
        fingerprint_source='nmap',
        last_seen=EXCLUDED.last_seen
    `)

    const txRaw = asmDb.transaction(rows => rows.forEach(r => rawIns.run(r)))
    const txSvc = asmDb.transaction(rows => rows.forEach(r => svcIns.run(r)))
    const rawRows = [], svcRows = []

    for (const block of hostBlocks) {
      // IP 주소 추출
      const ipMatch = block.match(/addrtype="ipv4"[^>]*addr="([^"]+)"/) || 
                      block.match(/addr="([^"]+)"[^>]*addrtype="ipv4"/)
      if (!ipMatch) continue
      const ip = ipMatch[1]

      // OS 추출
      const osMatch = block.match(/<osmatch[^>]*name="([^"]+)"/)
      const osName = osMatch ? osMatch[1] : null

      // 포트 블록 파싱
      const portBlocks = block.match(/<port[^>]+>[\s\S]*?<\/port>/g) || []
      if (!serviceMap[ip]) serviceMap[ip] = []

      for (const pb of portBlocks) {
        const portMatch    = pb.match(/portid="(\d+)"/)
        const protoMatch   = pb.match(/protocol="(\w+)"/)
        const stateMatch   = pb.match(/state="(\w+)"/)
        const svcNameMatch = pb.match(/name="([^"]+)"/)
        const prodMatch    = pb.match(/product="([^"]+)"/)
        const verMatch     = pb.match(/version="([^"]+)"/)
        const extraMatch   = pb.match(/extrainfo="([^"]+)"/)
        const cpeMatch     = pb.match(/<cpe>([^<]+)<\/cpe>/)

        const port    = portMatch    ? parseInt(portMatch[1])    : 0
        const proto   = protoMatch   ? protoMatch[1]   : 'tcp'
        const state   = stateMatch   ? stateMatch[1]   : 'unknown'
        const svc     = svcNameMatch ? svcNameMatch[1] : ''
        const prod    = prodMatch    ? prodMatch[1]    : ''
        const ver     = verMatch     ? verMatch[1]     : ''
        const extra   = extraMatch   ? extraMatch[1]   : ''
        const cpe     = cpeMatch     ? cpeMatch[1]     : ''

        if (state !== 'open') continue

        rawRows.push({ jobId: jobRes.lastInsertRowid, ip, port, proto, state, svc, prod, ver, extra, os: osName, cpe, script: null, raw: pb })
        svcRows.push({ ip, port, proto, state, svc, prod, ver, banner: `${prod} ${ver}`.trim(), extra, now: now() })
        serviceMap[ip].push({ port, proto, state, service: svc, product: prod, version: ver })
        count++
      }

      // asset 테이블에 OS 업데이트
      if (osName) {
        asmDb.prepare(`UPDATE asset SET os_name=@os, last_seen=@now WHERE ip=@ip`)
             .run({ os: osName, now: now(), ip })
      }
    }

    txRaw(rawRows)
    txSvc(svcRows)
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'nmap', `완료: ${count}개 서비스 탐지`)
  return serviceMap
}

// ─────────────────────────────────────────────────────────────
//  단계 7: httpx — 웹 배너/기술스택 식별
// ─────────────────────────────────────────────────────────────
async function runHttpx(runId, stageId, fqdns, ips, serviceMap) {
  // 웹 포트가 있는 대상 수집
  const targets = new Set()
  for (const fqdn of fqdns) targets.add(fqdn)
  for (const [ip, svcs] of Object.entries(serviceMap)) {
    for (const svc of svcs) {
      if ([80, 443, 8080, 8443, 8888, 9090].includes(svc.port)) {
        targets.add(`${ip}:${svc.port}`)
      }
    }
  }

  if (!targets.size) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'웹 대상 없음' })
    return []
  }

  const inFile  = tmpFile(runId, 'httpx_input.txt')
  const outFile = tmpFile(runId, 'httpx_output.json')
  fs.writeFileSync(inFile, [...targets].join('\n'))

  // ProjectDiscovery httpx 사용 (tools/httpx 우선)
  const HTTPX = TOOLS.httpx()
  // PD httpx 옵션: -l 파일입력, -json stdout, -o 파일출력
  const args = ['-l', inFile, '-json', '-o', outFile, '-silent',
                '-title', '-server', '-tech-detect',
                '-status-code', '-follow-redirects',
                '-timeout', '10', '-retries', '1']
  const cmdLine = `${HTTPX} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'httpx', `실행: ${cmdLine} (${targets.size}개 대상)`)

  try {
    await runCmd(HTTPX, args, { timeout: 300000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return []
  }

  const endpoints = []
  let count = 0

  if (fs.existsSync(outFile)) {
    const lines = fs.readFileSync(outFile, 'utf8').trim().split('\n').filter(Boolean)

    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('httpx-run'||@runId, 'httpx', 'web-targets', 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, s: now(), f: now(), cnt: lines.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_httpx (job_id, url, fqdn, ip, port, status_code, title, web_server, content_length, content_type, technology, jarm, tls_version, response_time_ms, redirect_chain, raw_json)
      VALUES (@jobId, @url, @fqdn, @ip, @port, @sc, @title, @server, @cl, @ct, @tech, @jarm, @tls, @rt, @redir, @raw)
    `)
    const epIns = asmDb.prepare(`
      INSERT INTO http_endpoint (asset_id, url, fqdn, ip, port, scheme, status_code, title, web_server, technology, tls_version, response_time_ms, redirect_url, first_seen, last_seen)
      SELECT a.id, @url, @fqdn, @ip, @port, @scheme, @sc, @title, @server, @tech, @tls, @rt, @redir, @now, @now
      FROM asset a WHERE a.ip=@ip
      ON CONFLICT (url) DO UPDATE SET
        fqdn=COALESCE(EXCLUDED.fqdn, http_endpoint.fqdn),
        ip=COALESCE(EXCLUDED.ip, http_endpoint.ip),
        port=COALESCE(EXCLUDED.port, http_endpoint.port),
        scheme=COALESCE(EXCLUDED.scheme, http_endpoint.scheme),
        status_code=EXCLUDED.status_code,
        title=COALESCE(EXCLUDED.title, http_endpoint.title),
        web_server=COALESCE(EXCLUDED.web_server, http_endpoint.web_server),
        technology=COALESCE(EXCLUDED.technology, http_endpoint.technology),
        tls_version=COALESCE(EXCLUDED.tls_version, http_endpoint.tls_version),
        response_time_ms=COALESCE(EXCLUDED.response_time_ms, http_endpoint.response_time_ms),
        redirect_url=COALESCE(EXCLUDED.redirect_url, http_endpoint.redirect_url),
        last_seen=EXCLUDED.last_seen
    `)

    const txRaw = asmDb.transaction(rows => rows.forEach(r => rawIns.run(r)))
    const txEp  = asmDb.transaction(rows => rows.forEach(r => epIns.run(r)))
    const rawRows = [], epRows = []

    for (const line of lines) {
      try {
        const obj   = JSON.parse(line)
        const url   = obj.url || obj.input || ''
        const sc    = obj.status_code || obj['status-code'] || 0
        const title = obj.title || ''
        const server = obj.webserver || obj.server || ''
        const techs  = JSON.stringify(obj.tech || obj.technologies || [])
        const rt     = obj.response_time ? Math.round(parseFloat(obj.response_time) * 1000) : 0
        const redir  = obj.final_url || obj.location || ''
        const tls    = obj.tls_data?.version || ''
        let fqdn = ''
        let ip = ''
        let port = 0
        let scheme = url.startsWith('https://') ? 'https' : 'http'
        try {
          const parsed = new URL(url)
          fqdn = /^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname) ? '' : parsed.hostname
          ip = /^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname) ? parsed.hostname : (obj.host || obj.ip || '')
          port = parsed.port ? parseInt(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80)
          scheme = parsed.protocol === 'https:' ? 'https' : 'http'
        } catch (_) {
          ip = obj.host || obj.ip || ''
        }

        rawRows.push({ jobId: jobRes.lastInsertRowid, url, fqdn, ip, port, sc, title, server, cl: obj.content_length||0, ct: obj.content_type||'', tech: techs, jarm: obj.jarm||'', tls, rt, redir, raw: line })
        if (ip) {
          epRows.push({ url, fqdn, ip, port, scheme, sc, title, server, tech: techs, tls, rt, redir, now: now() })
        }
        endpoints.push({ url, sc, title, server, tech: techs })
        count++
      } catch(_) {}
    }

    txRaw(rawRows)
    txEp(epRows)
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'httpx', `완료: ${count}개 HTTP 엔드포인트 발견`)
  return endpoints
}

// ─────────────────────────────────────────────────────────────
//  단계 8: Nuclei — 취약점 스캔
// ─────────────────────────────────────────────────────────────
async function runNuclei(runId, stageId, endpoints) {
  const webUrls = endpoints.filter(e => e.sc >= 100).map(e => e.url)
  if (!webUrls.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'웹 엔드포인트 없음' })
    return []
  }

  const inFile  = tmpFile(runId, 'nuclei_input.txt')
  const outFile = tmpFile(runId, 'nuclei_output.json')
  fs.writeFileSync(inFile, webUrls.join('\n'))

  // critical, high severity 위주 스캔 + 기술 탐지
  const NUCLEI = TOOLS.nuclei()
  const args = ['-l', inFile, '-json-export', outFile, '-silent',
                '-severity', 'critical,high,medium',
                '-tags', 'cve,exposure,misconfiguration,default-login',
                '-timeout', '10', '-retries', '1', '-bulk-size', '10',
                '-rate-limit', '50']
  const cmdLine = `${NUCLEI} ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'nuclei', `실행: ${cmdLine} (${webUrls.length}개 URL)`)

  try {
    await runCmd(NUCLEI, args, { timeout: 600000, runId })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return []
  }

  const findings = []
  let count = 0

  if (fs.existsSync(outFile)) {
    const lines = fs.readFileSync(outFile, 'utf8').trim().split('\n').filter(Boolean)

    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('nuclei-run'||@runId, 'nuclei', 'web-endpoints', 'done', @s, @f, @cnt)
      RETURNING id
    `).run({ runId, s: now(), f: now(), cnt: lines.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_nuclei (job_id, template_id, template_name, severity, cvss_score, cve_id, cwe_id, tags, target_url, target_ip, target_fqdn, target_port, matched_at, extracted_results, raw_json)
      VALUES (@jobId, @tid, @name, @sev, @cvss, @cve, @cwe, @tags, @targetUrl, @ip, @fqdn, @port, @matchedAt, @extr, @raw)
    `)
    const vulnIns = asmDb.prepare(`
      INSERT INTO vulnerability_finding (asset_id, ip, fqdn, url, port, service_name, template_id, template_name, severity, cvss_score, cve_id, cwe_id, tags, matched_at, extracted_results, status, first_seen, last_seen)
      SELECT
        COALESCE(
          (SELECT a.id FROM asset a WHERE @ip != '' AND a.ip=@ip LIMIT 1),
          (SELECT a.id FROM asset a JOIN asset_name an ON an.asset_id=a.id WHERE @fqdn != '' AND an.fqdn=@fqdn LIMIT 1)
        ),
        @ip, @fqdn, @url, @port, @svc, @tid, @name, @sev, @cvss, @cve, @cwe, @tags, @matchedAt, @extr, 'open', @now, @now
      ON CONFLICT DO NOTHING
    `)

    const txRaw  = asmDb.transaction(rows => rows.forEach(r => rawIns.run(r)))
    const txVuln = asmDb.transaction(rows => rows.forEach(r => vulnIns.run(r)))
    const rawRows = [], vulnRows = []

    for (const line of lines) {
      try {
        const obj = JSON.parse(line)
        const tid     = obj['template-id'] || obj.template_id || ''
        const name    = obj.info?.name || obj.template || tid
        const sev     = (obj.info?.severity || obj.severity || 'info').toLowerCase()
        const url     = obj['matched-at'] || obj.url || obj.matched || ''
        const cve     = (obj.info?.classification?.['cve-id'] || []).join(',')
        const cvss    = obj.info?.classification?.['cvss-score'] || null
        const cwe     = (obj.info?.classification?.['cwe-id'] || []).join(',')
        const extr    = JSON.stringify(obj['extracted-results'] || [])
        const tags    = (obj.info?.tags || []).join(',')

        // IP/FQDN 추출
        const ipMatch   = url.match(/https?:\/\/(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/)
        const hostMatch = url.match(/https?:\/\/([^/:]+)(?::(\d+))?/)
        const ip   = ipMatch   ? ipMatch[1]   : ''
        const fqdn = !ipMatch && hostMatch ? hostMatch[1] : ''
        const port = ipMatch ? parseInt(ipMatch[2]||'0') : (hostMatch ? parseInt(hostMatch[2]||'0') : 0)
        const matchedAt = obj['matched-at'] || obj.matched_at || url

        rawRows.push({ jobId: jobRes.lastInsertRowid, tid, name, sev, cvss, cve, cwe, tags, targetUrl: url, ip, fqdn, port, matchedAt, extr, raw: line })

        vulnRows.push({ ip, fqdn, tid, name, sev, cvss, cve, cwe, tags, url, port, svc: '', matchedAt, extr, now: now() })
        findings.push({ tid, name, sev, url, cve, cvss })
        count++
      } catch(_) {}
    }

    txRaw(rawRows)
    txVuln(vulnRows)
  }

  updateStage(stageId, { status:'done', finished_at: now(), result_count: count })
  log(runId, 'nuclei', `완료: ${count}개 취약점 발견`)
  return findings
}

// ─────────────────────────────────────────────────────────────
//  정규화: FQDN → asset / asset_name 등록
// ─────────────────────────────────────────────────────────────
function normalizeDiscoveredAssets(fqdnIpMap, domains) {
  const insAsset = asmDb.prepare(`
    INSERT INTO asset (ip, is_exposed, first_seen, last_seen)
    VALUES (@ip, 1, @now, @now)
    ON CONFLICT DO NOTHING
  `)
  const insName = asmDb.prepare(`
    INSERT INTO asset_name (asset_id, fqdn, root_domain, source)
    SELECT a.id, @fqdn, @root, @src
    FROM asset a WHERE a.ip=@ip
    ON CONFLICT DO NOTHING
  `)
  const updateSeen = asmDb.prepare(`UPDATE asset SET last_seen=@now WHERE ip=@ip`)

  const tx = asmDb.transaction(() => {
    for (const [fqdn, ips] of Object.entries(fqdnIpMap)) {
      for (const ip of ips) {
        insAsset.run({ ip, now: now() })
        updateSeen.run({ now: now(), ip })
        insName.run({
          fqdn,
          root: fqdn.split('.').slice(-2).join('.'),
          src: 'dnsx',
          ip
        })
      }
    }
  })
  tx()

  log(0, 'normalize', `자산 정규화 완료: ${Object.keys(fqdnIpMap).length}개 FQDN 처리`)
}

// ─────────────────────────────────────────────────────────────
//  변경 감지 (Change Detection)
// ─────────────────────────────────────────────────────────────
function detectChanges(runId) {
  // 새 자산 탐지 (오늘 first_seen이 today인 자산)
  const today = now().slice(0,10)
  const newAssets = asmDb.prepare(`
    SELECT ip FROM asset WHERE first_seen LIKE @today||'%'
  `).all({ today })

  const logIns = asmDb.prepare(`
    INSERT INTO asset_change_log (change_type, asset_ip, asset_id, detail, severity, detected_at)
    SELECT 'new_asset', a.ip, a.id, @detail, 'info', @now
    FROM asset a WHERE a.ip=@ip
    ON CONFLICT DO NOTHING
  `)
  const tx = asmDb.transaction(rows => rows.forEach(r => logIns.run(r)))
  tx(newAssets.map(a => ({ ip: a.ip, now: now(), detail: JSON.stringify({ msg: '신규 자산 발견', ip: a.ip }) })))

  log(runId, 'detect-changes', `변경 감지: 신규 자산 ${newAssets.length}개`)
}

// ─────────────────────────────────────────────────────────────
//  메인 파이프라인 실행
// ─────────────────────────────────────────────────────────────
async function runPipeline(runId) {
  const targets     = getActiveTargets()
  const ipRanges    = targets.filter(t => t.type==='ip_range').map(t => t.value)
  const domainList  = targets.filter(t => t.type==='domain').map(t => t.value)

  log(runId, 'start', `파이프라인 시작 — IP대역: ${ipRanges.length}개, 도메인: ${domainList.length}개`)
  log(runId, 'start', `tools/ 디렉토리: ${TOOLS_DIR}`)
  validateTools()  // 툴 경로 로그 출력

  // 단계 로그 생성
  const stages = ['amass','subfinder','dnsx','naabu','masscan','nmap','httpx','nuclei']
  const stageIds = {}
  for (const s of stages) stageIds[s] = createStageLog(runId, s)

  updateRun(runId, { status:'running', started_at: now(), total_stages: stages.length, done_stages: 0 })

  let fqdnsAmass    = []
  let fqdnsSubfinder = []
  let allFqdns      = []
  let fqdnIpMap     = {}
  let discoveredIps = []
  let naabuPortMap  = {}
  let masscanPortMap = {}
  let nmapServiceMap = {}
  let httpEndpoints  = []

  try {
    // ── 1. Amass
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'amass', done_stages: 0 })
    fqdnsAmass = await runAmass(runId, stageIds['amass'], domainList)

    // ── 2. Subfinder
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'subfinder', done_stages: 1 })
    fqdnsSubfinder = await runSubfinder(runId, stageIds['subfinder'], domainList)

    // 중복 제거 병합
    allFqdns = [...new Set([...domainList, ...fqdnsAmass, ...fqdnsSubfinder])]
    log(runId, 'merge', `총 FQDN ${allFqdns.length}개 (amass:${fqdnsAmass.length} + subfinder:${fqdnsSubfinder.length})`)

    // ── 3. dnsx
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'dnsx', done_stages: 2 })
    const dnsxResult = await runDnsx(runId, stageIds['dnsx'], allFqdns)
    fqdnIpMap    = dnsxResult.fqdnIpMap
    discoveredIps = dnsxResult.ips

    // FQDN → asset 정규화
    normalizeDiscoveredAssets(fqdnIpMap, domainList)

    // ── 4. Naabu  (dnsx 발견 IP 대상, top-1000 포트 빠른 확인)
    // • 입력: discoveredIps (FQDN → dnsx 매핑 IP만)
    // • 역할: 살아있는 호스트 + 주요 서비스 포트 빠르게 확인
    // • ipRanges는 넣지 않음 — CIDR은 Masscan이 전체포트로 담당
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'naabu', done_stages: 3 })
    naabuPortMap = await runNaabu(runId, stageIds['naabu'], discoveredIps)

    // ── 5. Masscan  (전체 자산 대상, 전체포트 1-65535)
    // • 입력: discoveredIps(도메인→IP) + ipRanges(CIDR) 모두
    // • 역할: 도메인/CIDR 구분 없이 모든 확인된 자산의 65535번까지 전수조사
    // • 권한 부족(root 필요) 시 graceful skip
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'masscan', done_stages: 4 })
    masscanPortMap = await runMasscan(runId, stageIds['masscan'], discoveredIps, ipRanges)

    // ── 6. Nmap
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'nmap', done_stages: 5 })
    nmapServiceMap = await runNmap(runId, stageIds['nmap'], naabuPortMap, masscanPortMap)

    // ── 7. httpx
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'httpx', done_stages: 6 })
    httpEndpoints = await runHttpx(runId, stageIds['httpx'], allFqdns, discoveredIps, nmapServiceMap)

    // ── 8. Nuclei
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'nuclei', done_stages: 7 })
    const vulnFindings = await runNuclei(runId, stageIds['nuclei'], httpEndpoints)

    // ── 변경 감지
    detectChanges(runId)

    // ── asset_current 뷰 갱신
    try { refreshAssetCurrent() } catch(e) {
      log(runId, 'refresh', `asset_current 갱신 실패: ${e.message}`)
    }

    // ── 완료 요약
    const summary = {
      new_fqdns:    allFqdns.length,
      new_ips:      discoveredIps.length,
      open_ports:   Object.values(naabuPortMap).reduce((s, p) => s + p.length, 0),
      services:     Object.values(nmapServiceMap).reduce((s, p) => s + p.length, 0),
      endpoints:    httpEndpoints.length,
      vulns:        vulnFindings.length
    }

    finalizeRun(runId, 'done', summary)
    log(runId, 'done', `파이프라인 완료: ${JSON.stringify(summary)}`)

  } catch(err) {
    log(runId, 'error', `파이프라인 오류: ${err.message}\n${err.stack}`)
    finalizeRun(runId, 'failed', null, err.message)
  }
}

function finalizeRun(runId, status, summary = null, errorMsg = null) {
  updateRun(runId, {
    status,
    finished_at: now(),
    done_stages: status === 'done' ? 8 : undefined,
    current_stage: null,
    cancel_requested: status === 'cancelled' ? 1 : 0,
    summary_json: summary ? JSON.stringify(summary) : null,
    error_msg: errorMsg
  })
  activeRuns.delete(runId)
  log(runId, 'finalize', `파이프라인 상태: ${status}`)
}

// ─────────────────────────────────────────────────────────────
//  공개 API
// ─────────────────────────────────────────────────────────────

/** 파이프라인 시작 (비동기, 즉시 runId 반환) */
function startPipeline(triggeredBy = 'manual') {
  const running = asmDb.prepare(`
    SELECT id FROM pipeline_run
    WHERE status IN ('pending','running') AND COALESCE(cancel_requested, 0)=0
    ORDER BY id DESC LIMIT 1
  `).get()
  if (running) {
    throw new Error(`이미 실행 중인 파이프라인이 있습니다. (Run #${running.id})`)
  }

  const res = asmDb.prepare(`
    INSERT INTO pipeline_run (status, triggered_by, created_at, cancel_requested)
    VALUES ('pending', @by, @now, 0)
    RETURNING id
  `).run({ by: triggeredBy, now: now() })

  const runId = res.lastInsertRowid
  activeRuns.set(runId, { cancelled: false })

  // 비동기 실행 (즉시 반환)
  setImmediate(() => runPipeline(runId))

  return runId
}

/** 파이프라인 취소 */
function cancelPipeline(runId) {
  const run = asmDb.prepare('SELECT id, status FROM pipeline_run WHERE id=?').get(runId)
  if (!run || !['pending', 'running'].includes(run.status)) return false

  updateRun(runId, {
    cancel_requested: 1,
    error_msg: '사용자 중단 요청'
  })

  const r = activeRuns.get(runId)
  if (r) {
    r.cancelled = true
    if (r.currentChild && !r.currentChild.killed) {
      r.currentChild.kill('SIGTERM')
      setTimeout(() => {
        if (r.currentChild && !r.currentChild.killed) r.currentChild.kill('SIGKILL')
      }, 3000)
    }
  } else {
    updateRun(runId, { status: 'cancelled', finished_at: now() })
  }
  return true
}

/** 파이프라인 상태 조회 */
function getPipelineStatus(runId) {
  const run = asmDb.prepare('SELECT * FROM pipeline_run WHERE id=?').get(runId)
  if (!run) return null
  const stages = asmDb.prepare('SELECT * FROM pipeline_stage_log WHERE run_id=? ORDER BY id').all(runId)
  return { run, stages }
}

/** 파이프라인 목록 */
function getPipelineList(limit = 20) {
  return asmDb.prepare(`
    SELECT * FROM pipeline_run ORDER BY id DESC LIMIT ?
  `).all(limit)
}

module.exports = { startPipeline, cancelPipeline, getPipelineStatus, getPipelineList }
