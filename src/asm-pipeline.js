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

const { execFile, spawn } = require('child_process')
const { promisify }        = require('util')
const path   = require('path')
const fs     = require('fs')
const os     = require('os')
const { asmDb, refreshAssetCurrent } = require('./asm-db')

const execFileAsync = promisify(execFile)

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
  return r && r.cancelled
}

// ─────────────────────────────────────────────────────────────
//  명령 실행 헬퍼
// ─────────────────────────────────────────────────────────────
function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const timeout = opts.timeout || 300000  // 기본 5분
    let stdout = '', stderr = ''
    const child = spawn(cmd, args, { timeout })
    child.stdout.on('data', d => { stdout += d.toString() })
    child.stderr.on('data', d => { stderr += d.toString() })
    child.on('close', code => {
      resolve({ code, stdout, stderr })
    })
    child.on('error', err => {
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
  const args = ['enum', '-passive', '-d', domains.join(','), '-o', outFile, '-silent']
  const cmdLine = `amass ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'amass', `실행: ${cmdLine}`)

  let result
  try {
    result = await runCmd('amass', args, { timeout: 180000 })
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

  const domainArgs = domains.flatMap(d => ['-d', d])
  const args = [...domainArgs, '-silent', '-all']
  const cmdLine = `subfinder ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'subfinder', `실행: ${cmdLine}`)

  let result
  try {
    result = await runCmd('subfinder', args, { timeout: 120000 })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return []
  }

  const fqdns = result.stdout.trim().split('\n').filter(Boolean).map(l => l.trim())

  if (fqdns.length > 0) {
    const jobRes = asmDb.prepare(`
      INSERT INTO scan_job (job_name, tool, target_scope, status, started_at, finished_at, result_count)
      VALUES ('subfinder-run'||@runId, 'subfinder', @scope, 'done', @s, @f, @cnt)
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
  const args = ['-l', inFile, '-a', '-resp', '-json', '-silent', '-retry', '2']
  const cmdLine = `dnsx ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'dnsx', `실행: ${cmdLine} (${allFqdns.length}개 FQDN)`)

  let result
  try {
    result = await runCmd('dnsx', args, { timeout: 120000 })
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
//  단계 4: Naabu — 빠른 포트 스캔
// ─────────────────────────────────────────────────────────────
async function runNaabu(runId, stageId, ips, ipRanges) {
  const allTargets = [...new Set([...ips, ...ipRanges])]
  if (!allTargets.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'IP 대상 없음' })
    return {}
  }

  const inFile  = tmpFile(runId, 'naabu_input.txt')
  const outFile = tmpFile(runId, 'naabu_output.txt')
  fs.writeFileSync(inFile, allTargets.join('\n'))

  // 주요 포트만 스캔 (빠른 탐지용)
  const topPorts = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443,8888,9090,9200,27017'
  const args = ['-l', inFile, '-p', topPorts, '-o', outFile, '-silent', '-rate', '1000', '-timeout', '3']
  const cmdLine = `naabu ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'naabu', `실행: ${cmdLine}`)

  try {
    await runCmd('naabu', args, { timeout: 300000 })
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
  log(runId, 'naabu', `완료: ${count}개 오픈 포트 발견`)
  return portMap
}

// ─────────────────────────────────────────────────────────────
//  단계 5: Masscan — 대규모 포트 스캔 (IP 대역 전용)
// ─────────────────────────────────────────────────────────────
async function runMasscan(runId, stageId, ipRanges) {
  if (!ipRanges.length) {
    updateStage(stageId, { status:'skipped', finished_at: now(), result_count:0, error_msg:'IP 대역 없음' })
    return {}
  }

  const outFile = tmpFile(runId, 'masscan_output.json')
  // masscan은 root 권한 필요 - 없으면 skip
  const args = [...ipRanges, '-p', '80,443,22,21,8080,8443,3389,3306,445,139', '--rate', '1000', '-oJ', outFile]
  const cmdLine = `masscan ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'masscan', `실행: ${cmdLine}`)

  let result
  try {
    result = await runCmd('masscan', args, { timeout: 300000 })
  } catch(e) {
    updateStage(stageId, { status:'failed', finished_at: now(), error_msg: e.message })
    return {}
  }

  const portMap = {}
  let count = 0

  if (result.code !== 0 && result.stderr.includes('permission')) {
    updateStage(stageId, { status:'skipped', finished_at: now(), error_msg:'root 권한 필요 - Naabu 결과 사용' })
    log(runId, 'masscan', '권한 부족 - 단계 스킵')
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
      `).run({ runId, scope: ipRanges.join(','), s: now(), f: now(), cnt: records.length })

      const ins = asmDb.prepare(`
        INSERT INTO raw_masscan (job_id, ip, port, protocol, state, raw_json)
        VALUES (@jobId, @ip, @port, @proto, 'open', @raw)
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
  log(runId, 'masscan', `완료: ${count}개 오픈 포트 발견`)
  return portMap
}

// ─────────────────────────────────────────────────────────────
//  단계 6: Nmap — 서비스/버전 탐지
// ─────────────────────────────────────────────────────────────
async function runNmap(runId, stageId, naabuPortMap, masscanPortMap) {
  // Naabu + Masscan 결과 병합
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

  const args = ['-sV', '-sC', '--open', '-p', ports, '-oX', outFile, '--host-timeout', '30s', '-T4', ...ips]
  const cmdLine = `nmap ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'nmap', `실행: ${cmdLine} (${ips.length}개 IP)`)

  let result
  try {
    result = await runCmd('nmap', args, { timeout: 600000 })
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
    `).run({ runId, scope: ips.slice(0,3).join(','), s: now(), f: now(), cnt: hostBlocks.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_nmap (job_id, ip, port, protocol, state, service_name, product, version, extra_info, os_name, cpe, script_output, raw_xml)
      VALUES (@jobId, @ip, @port, @proto, @state, @svc, @prod, @ver, @extra, @os, @cpe, @script, @raw)
    `)
    const svcIns = asmDb.prepare(`
      INSERT OR REPLACE INTO network_service (asset_id, port, protocol, state, service_name, product, version, banner, extra_info, last_seen)
      SELECT a.id, @port, @proto, @state, @svc, @prod, @ver, @banner, @extra, @now
      FROM asset a WHERE a.ip=@ip
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

  const args = ['-l', inFile, '-json', '-o', outFile, '-silent', '-title', '-server', '-tech-detect',
                '-status-code', '-follow-redirects', '-timeout', '10', '-retries', '1']
  const cmdLine = `httpx ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'httpx', `실행: ${cmdLine} (${targets.size}개 대상)`)

  try {
    await runCmd('httpx', args, { timeout: 300000 })
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
    `).run({ runId, s: now(), f: now(), cnt: lines.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_httpx (job_id, url, status_code, title, web_server, content_length, content_type, technology, jarm, tls_version, response_time_ms, redirect_url, raw_json)
      VALUES (@jobId, @url, @sc, @title, @server, @cl, @ct, @tech, @jarm, @tls, @rt, @redir, @raw)
    `)
    const epIns = asmDb.prepare(`
      INSERT OR REPLACE INTO http_endpoint (asset_id, url, status_code, title, web_server, technology_json, tls_version, response_time_ms, redirect_url, last_seen)
      SELECT a.id, @url, @sc, @title, @server, @tech, @tls, @rt, @redir, @now
      FROM asset a WHERE a.ip=@ip
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
        const techs  = (obj.tech || obj.technologies || []).join(',')
        const rt     = obj.response_time ? Math.round(parseFloat(obj.response_time) * 1000) : 0
        const redir  = obj.final_url || obj.location || ''
        const tls    = obj.tls_data?.version || ''

        rawRows.push({ jobId: jobRes.lastInsertRowid, url, sc, title, server, cl: obj.content_length||0, ct: obj.content_type||'', tech: techs, jarm: obj.jarm||'', tls, rt, redir, raw: line })

        // IP 추출 (URL에서)
        const ipMatch = url.match(/https?:\/\/(\d+\.\d+\.\d+\.\d+)/)
        const ip = ipMatch ? ipMatch[1] : (obj.host || '')
        if (ip) {
          epRows.push({ url, sc, title, server, tech: techs, tls, rt, redir, now: now(), ip })
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
  const args = ['-l', inFile, '-json-export', outFile, '-silent',
                '-severity', 'critical,high,medium',
                '-tags', 'cve,exposure,misconfiguration,default-login',
                '-timeout', '10', '-retries', '1', '-bulk-size', '10',
                '-rate-limit', '50']
  const cmdLine = `nuclei ${args.join(' ')}`
  updateStage(stageId, { status:'running', started_at: now(), command_line: cmdLine })
  log(runId, 'nuclei', `실행: ${cmdLine} (${webUrls.length}개 URL)`)

  try {
    await runCmd('nuclei', args, { timeout: 600000 })
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
    `).run({ runId, s: now(), f: now(), cnt: lines.length })

    const rawIns = asmDb.prepare(`
      INSERT INTO raw_nuclei (job_id, template_id, template_name, severity, matched_url, extracted_results, matcher_name, cve_id, cvss_score, cwe_id, raw_json)
      VALUES (@jobId, @tid, @name, @sev, @url, @extr, @matcher, @cve, @cvss, @cwe, @raw)
    `)
    const vulnIns = asmDb.prepare(`
      INSERT OR IGNORE INTO vulnerability_finding (asset_id, template_id, template_name, severity, cvss_score, cve_id, cwe_id, matched_url, port, service_name, extracted_results, status, first_seen, last_seen)
      SELECT 
        COALESCE(
          (SELECT a.id FROM asset a 
           WHERE @ip != '' AND a.ip=@ip LIMIT 1),
          (SELECT a.id FROM asset a 
           JOIN asset_name an ON an.asset_id=a.id 
           WHERE @fqdn != '' AND an.fqdn=@fqdn LIMIT 1)
        ),
        @tid, @name, @sev, @cvss, @cve, @cwe, @url, @port, @svc,
        @extr, 'open', @now, @now
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
        const matcher = obj['matcher-name'] || ''

        rawRows.push({ jobId: jobRes.lastInsertRowid, tid, name, sev, url, extr, matcher, cve, cvss, cwe, raw: line })

        // IP/FQDN 추출
        const ipMatch   = url.match(/https?:\/\/(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/)
        const hostMatch = url.match(/https?:\/\/([^/:]+)(?::(\d+))?/)
        const ip   = ipMatch   ? ipMatch[1]   : ''
        const fqdn = !ipMatch && hostMatch ? hostMatch[1] : ''
        const port = ipMatch ? parseInt(ipMatch[2]||'0') : (hostMatch ? parseInt(hostMatch[2]||'0') : 0)

        vulnRows.push({ ip, fqdn, tid, name, sev, cvss, cve, cwe, url, port, svc: '', extr, now: now() })
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
    INSERT OR IGNORE INTO asset (ip, is_exposed, first_seen, last_seen)
    VALUES (@ip, 1, @now, @now)
  `)
  const insName = asmDb.prepare(`
    INSERT OR IGNORE INTO asset_name (asset_id, fqdn, root_domain, source)
    SELECT a.id, @fqdn, @root, @src
    FROM asset a WHERE a.ip=@ip
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
    INSERT INTO asset_change_log (asset_id, change_type, field_name, new_value, detected_at)
    SELECT a.id, 'new_asset', 'ip', a.ip, @now
    FROM asset a WHERE a.ip=@ip
  `)
  const tx = asmDb.transaction(rows => rows.forEach(r => logIns.run(r)))
  tx(newAssets.map(a => ({ ip: a.ip, now: now() })))

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

    // ── 4. Naabu
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'naabu', done_stages: 3 })
    naabuPortMap = await runNaabu(runId, stageIds['naabu'], discoveredIps, ipRanges)

    // ── 5. Masscan
    if (isCancelled(runId)) return finalizeRun(runId, 'cancelled')
    updateRun(runId, { current_stage: 'masscan', done_stages: 4 })
    masscanPortMap = await runMasscan(runId, stageIds['masscan'], ipRanges)

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
  const res = asmDb.prepare(`
    INSERT INTO pipeline_run (status, triggered_by, created_at)
    VALUES ('pending', @by, @now)
  `).run({ by: triggeredBy, now: now() })

  const runId = res.lastInsertRowid
  activeRuns.set(runId, { cancelled: false })

  // 비동기 실행 (즉시 반환)
  setImmediate(() => runPipeline(runId))

  return runId
}

/** 파이프라인 취소 */
function cancelPipeline(runId) {
  const r = activeRuns.get(runId)
  if (r) {
    r.cancelled = true
    updateRun(runId, { status: 'cancelled', finished_at: now() })
    return true
  }
  return false
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
