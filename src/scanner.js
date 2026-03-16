'use strict'
/**
 * ASM 스캔 파이프라인 엔진
 *
 * 실행 흐름:
 *   Stage 1: Amass     — 도메인 → 서브도메인/IP 탐지
 *   Stage 2: Subfinder — 도메인 → 서브도메인 탐지
 *   Stage 3: dnsx      — FQDN 목록 → DNS 확인/IP 매핑
 *   Stage 4: Naabu     — IP 목록 → 포트 스캔 (빠른 TCP)
 *   Stage 5: Masscan   — IP 대역 → 대규모 포트 스캔
 *   Stage 6: Nmap      — (Naabu+Masscan 결과 IP:Port) → 서비스 탐지/버전
 *   Stage 7: httpx     — IP:Port/FQDN → 웹 배너·기술스택
 *   ── 위 7단계 완료 후 asset_current 집계 갱신 ──
 *   Stage 8: Nuclei    — asset_current IP 목록 → 취약점 스캔
 *
 * 설계 원칙:
 *   - Raw Zone에 모든 툴 출력 원문 보존
 *   - Normalized Zone으로 파싱·정규화
 *   - 서비스 fingerprint는 Nmap 결과 우선
 *   - 화면에는 Raw 결과를 직접 노출하지 않음
 */

const { spawn }  = require('child_process')
const path       = require('path')
const fs         = require('fs')
const os         = require('os')
const { asmDb, refreshAssetCurrent } = require('./asm-db')

// tools/ 내 배치된 ASM 바이너리 우선 사용 (예: /SocOpsASM/tools/nmap)
const TOOLS_DIR = path.join(__dirname, '../tools')
function _resolveTool(cmd) {
  const local = path.join(TOOLS_DIR, cmd)
  if (fs.existsSync(local)) return local
  return cmd
}

// ─── 상수 ────────────────────────────────────────────────────
const TOOL_TIMEOUT_MS = 10 * 60 * 1000   // 스테이지당 최대 10분
const TMP_DIR = path.join(os.tmpdir(), 'asm-scan')
if (!fs.existsSync(TMP_DIR)) fs.mkdirSync(TMP_DIR, { recursive: true })

// 현재 실행 중인 파이프라인 상태 (단일 인스턴스)
let _runningPipelineId = null
let _cancelRequested   = false

// ─── 공개 API ─────────────────────────────────────────────────

/**
 * 새 파이프라인 실행 시작
 * @returns {number} pipeline_run.id
 */
function startPipeline(triggeredBy = 'manual') {
  if (_runningPipelineId !== null) {
    throw new Error(`이미 실행 중인 파이프라인이 있습니다 (run_id=${_runningPipelineId})`)
  }

  const enabledTargets = asmDb.prepare(
    "SELECT * FROM scan_target WHERE enabled = 1"
  ).all()
  if (enabledTargets.length === 0) {
    throw new Error('활성화된 스캔 대상이 없습니다. 스캔 대상을 먼저 등록해주세요.')
  }

  // pipeline_run 레코드 생성
  const runId = asmDb.prepare(`
    INSERT INTO pipeline_run (status, triggered_by, started_at, current_stage)
    VALUES ('running', ?, datetime('now','localtime'), 'amass')
  `).run(triggeredBy).lastInsertRowid

  _runningPipelineId = runId
  _cancelRequested   = false

  // 비동기 실행 (await 없이 백그라운드)
  _executePipeline(runId, enabledTargets).catch(err => {
    console.error(`[SCANNER] 파이프라인 ${runId} 치명적 오류:`, err)
    _finishPipeline(runId, 'failed', err.message)
  })

  return runId
}

function cancelPipeline() {
  _cancelRequested = true
}

function getRunningPipelineId() { return _runningPipelineId }

// ─── 내부 실행 로직 ───────────────────────────────────────────

async function _executePipeline(runId, targets) {
  console.log(`[SCANNER] 파이프라인 ${runId} 시작 — 대상 ${targets.length}개`)

  const ipRanges  = targets.filter(t => t.type === 'ip_range').map(t => t.value)
  const domains   = targets.filter(t => t.type === 'domain').map(t => t.value)

  let collectedIPs   = new Set()   // Stage 1-3에서 수집한 IP 목록
  let collectedFQDNs = new Set()   // Stage 1-3에서 수집한 FQDN 목록
  let openPortMap    = {}          // { ip: Set<port> } Stage 4-5 결과
  let naabuResults   = []          // { ip, port }
  let stagesDone = 0

  try {
    // ══ Stage 1: Amass ══════════════════════════════════════════
    if (!_cancelRequested && domains.length > 0) {
      await _runStage(runId, 'amass', async (log) => {
        for (const domain of domains) {
          const lines = await _runTool('amass', [
            'enum', '-passive', '-d', domain,
            '-timeout', '3', '-json',
          ], log, { timeout: 5 * 60 * 1000 })

          let count = 0
          for (const line of lines) {
            try {
              const obj = JSON.parse(line)
              // amass JSON 구조: { name, domain, addresses:[{ip,cidr,asn,desc}], sources, tag }
              const fqdn    = obj.name || ''
              const rootDom = obj.domain || domain
              const sources = (obj.sources || []).join(',')
              const cdnTag  = obj.tag || null

              if (!fqdn) continue
              collectedFQDNs.add(fqdn)

              for (const addr of (obj.addresses || [])) {
                const ip = addr.ip
                if (!ip) continue
                collectedIPs.add(ip)

                // raw_amass 저장
                asmDb.prepare(`
                  INSERT INTO raw_amass (job_id, fqdn, root_domain, record_type, answer, source, asn, cidr, org, cdn, raw_json)
                  VALUES (?, ?, ?, 'A', ?, ?, ?, ?, ?, ?, ?)
                `).run(
                  runId, fqdn, rootDom, ip, sources,
                  String(addr.asn || ''), addr.cidr || null,
                  addr.desc || null, cdnTag,
                  JSON.stringify(obj)
                )
                count++
              }
            } catch {}
          }
          return count
        }
      })
    } else if (domains.length === 0) {
      _skipStage(runId, 'amass', '도메인 대상 없음')
    }
    stagesDone++; _updateProgress(runId, stagesDone, 'subfinder')

    // ══ Stage 2: Subfinder ══════════════════════════════════════
    if (!_cancelRequested && domains.length > 0) {
      await _runStage(runId, 'subfinder', async (log) => {
        let count = 0
        for (const domain of domains) {
          const lines = await _runTool('subfinder', [
            '-d', domain, '-silent', '-all',
          ], log)

          for (const line of lines) {
            const fqdn = line.trim()
            if (!fqdn || !fqdn.includes('.')) continue
            collectedFQDNs.add(fqdn)

            asmDb.prepare(`
              INSERT INTO raw_subfinder (job_id, fqdn, root_domain, source, raw_line)
              VALUES (?, ?, ?, 'subfinder', ?)
            `).run(runId, fqdn, domain, fqdn)
            count++
          }
        }
        return count
      })
    } else if (domains.length === 0) {
      _skipStage(runId, 'subfinder', '도메인 대상 없음')
    }
    stagesDone++; _updateProgress(runId, stagesDone, 'dnsx')

    // ══ Stage 3: dnsx ═══════════════════════════════════════════
    // FQDN 목록을 파일로 저장 후 dnsx에 전달
    if (!_cancelRequested && collectedFQDNs.size > 0) {
      await _runStage(runId, 'dnsx', async (log) => {
        const fqdnFile = path.join(TMP_DIR, `dnsx_input_${runId}.txt`)
        fs.writeFileSync(fqdnFile, [...collectedFQDNs].join('\n'))

        const lines = await _runTool('dnsx', [
          '-l', fqdnFile, '-a', '-resp', '-json', '-silent',
        ], log)

        let count = 0
        for (const line of lines) {
          try {
            const obj = JSON.parse(line)
            // dnsx JSON: { host, resolver, a:["1.2.3.4"], status_code, ... }
            const fqdn = obj.host || ''
            for (const ip of (obj.a || [])) {
              collectedIPs.add(ip)
              asmDb.prepare(`
                INSERT INTO raw_dnsx (job_id, fqdn, record_type, answer, status_code, raw_json)
                VALUES (?, ?, 'A', ?, ?, ?)
              `).run(runId, fqdn, ip, obj.status_code || 'NOERROR', JSON.stringify(obj))

              // Normalized: asset + asset_name
              _upsertAssetAndName(ip, fqdn, 'A', 'dnsx')
              count++
            }
          } catch {}
        }
        try { fs.unlinkSync(fqdnFile) } catch {}
        return count
      })
    } else {
      _skipStage(runId, 'dnsx', 'FQDN 수집 결과 없음')
    }

    // IP 대역에서 직접 IP도 추가
    for (const range of ipRanges) { collectedIPs.add(range) }

    stagesDone++; _updateProgress(runId, stagesDone, 'naabu')

    // ══ Stage 4: Naabu — 빠른 TCP 포트 스캔 ═════════════════════
    if (!_cancelRequested && collectedIPs.size > 0) {
      await _runStage(runId, 'naabu', async (log) => {
        const ipFile = path.join(TMP_DIR, `naabu_input_${runId}.txt`)
        fs.writeFileSync(ipFile, [...collectedIPs].join('\n'))

        const lines = await _runTool('naabu', [
          '-l', ipFile,
          '-p', '80,443,8080,8443,22,21,25,3306,3389,445,6379,27017,9200,5432',
          '-silent', '-json',
          '-rate', '1000',
          '-c', '50',
        ], log)

        let count = 0
        for (const line of lines) {
          try {
            const obj = JSON.parse(line)
            const ip   = obj.ip   || obj.host
            const port = obj.port
            if (!ip || !port) continue

            if (!openPortMap[ip]) openPortMap[ip] = new Set()
            openPortMap[ip].add(port)
            naabuResults.push({ ip, port, protocol: 'tcp' })

            asmDb.prepare(`
              INSERT INTO raw_naabu (job_id, ip, port, protocol, raw_line)
              VALUES (?, ?, ?, 'tcp', ?)
            `).run(runId, ip, port, JSON.stringify(obj))
            count++
          } catch {}
        }
        try { fs.unlinkSync(ipFile) } catch {}
        return count
      })
    } else {
      _skipStage(runId, 'naabu', '수집된 IP 없음')
    }
    stagesDone++; _updateProgress(runId, stagesDone, 'masscan')

    // ══ Stage 5: Masscan — 대규모 포트 스캔 (IP 대역만) ══════════
    if (!_cancelRequested && ipRanges.length > 0) {
      await _runStage(runId, 'masscan', async (log) => {
        let count = 0
        for (const range of ipRanges) {
          const lines = await _runTool('masscan', [
            range,
            '-p', '1-1024,3306,3389,5432,6379,8080,8443,8888,9200,27017',
            '--rate', '1000',
            '--output-format', 'json',
            '--output-filename', '-',
          ], log, { sudo: true })

          for (const line of lines) {
            const clean = line.replace(/^,?\s*/, '').trim()
            if (!clean || clean === '[' || clean === ']') continue
            try {
              const obj = JSON.parse(clean)
              const ip   = obj.ip
              const port = obj.ports && obj.ports[0] ? obj.ports[0].port : null
              const proto= obj.ports && obj.ports[0] ? (obj.ports[0].proto || 'tcp') : 'tcp'
              if (!ip || !port) continue

              if (!openPortMap[ip]) openPortMap[ip] = new Set()
              openPortMap[ip].add(port)
              collectedIPs.add(ip)

              asmDb.prepare(`
                INSERT INTO raw_masscan (job_id, ip, port, protocol, raw_json)
                VALUES (?, ?, ?, ?, ?)
              `).run(runId, ip, port, proto, JSON.stringify(obj))
              count++
            } catch {}
          }
        }
        return count
      })
    } else {
      _skipStage(runId, 'masscan', 'IP 대역 대상 없음')
    }
    stagesDone++; _updateProgress(runId, stagesDone, 'nmap')

    // ══ Stage 6: Nmap — 서비스 탐지/버전 ════════════════════════
    if (!_cancelRequested && Object.keys(openPortMap).length > 0) {
      await _runStage(runId, 'nmap', async (log) => {
        let count = 0
        // IP별로 해당 오픈 포트에만 Nmap 실행 (효율화)
        const ipList = Object.keys(openPortMap).slice(0, 50)  // 최대 50 IP

        for (const ip of ipList) {
          if (_cancelRequested) break
          const ports = [...openPortMap[ip]].join(',')
          if (!ports) continue

          const xmlFile = path.join(TMP_DIR, `nmap_${ip.replace(/[./]/g,'_')}_${runId}.xml`)
          const lines = await _runTool('nmap', [
            '-sV', '--version-intensity', '5',
            '-p', ports,
            '-oX', xmlFile,
            '--open',
            ip,
          ], log)

          // XML 파싱
          try {
            const xml = fs.readFileSync(xmlFile, 'utf8')
            const portMatches = [...xml.matchAll(/<port protocol="(\w+)" portid="(\d+)">[\s\S]*?<state state="(\w+)"[\s\S]*?<service name="([^"]*)"(?:[^>]*product="([^"]*)")?(?:[^>]*version="([^"]*)")?(?:[^>]*extrainfo="([^"]*)")?/g)]
            for (const m of portMatches) {
              const [, protocol, portStr, state, service, product, version, extraInfo] = m
              const port = parseInt(portStr)

              asmDb.prepare(`
                INSERT INTO raw_nmap (job_id, ip, port, protocol, state, service_name, product, version, extra_info, raw_xml)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).run(runId, ip, port, protocol, state, service||null, product||null, version||null, extraInfo||null, xml.slice(0, 2000))

              if (state === 'open') {
                _upsertNetworkService(ip, port, protocol, state, service, product, version, 'nmap')
              }
              count++
            }
            fs.unlinkSync(xmlFile)
          } catch {}
        }
        return count
      })
    } else {
      _skipStage(runId, 'nmap', '오픈 포트 결과 없음')
    }
    stagesDone++; _updateProgress(runId, stagesDone, 'httpx')

    // ══ Stage 7: httpx — 웹 배너·기술스택 ══════════════════════
    // 입력: IP:Port 조합 + FQDN 목록
    if (!_cancelRequested) {
      await _runStage(runId, 'httpx', async (log) => {
        const httpTargets = new Set()

        // 오픈 포트 중 웹 포트에 대해 http/https URL 생성
        const WEB_PORTS = { 80:'http', 8080:'http', 443:'https', 8443:'https', 8888:'http', 3000:'http', 5000:'http' }
        for (const [ip, ports] of Object.entries(openPortMap)) {
          for (const port of ports) {
            if (WEB_PORTS[port]) {
              httpTargets.add(`${WEB_PORTS[port]}://${ip}:${port}`)
            }
          }
        }
        // FQDN도 추가
        for (const fqdn of collectedFQDNs) {
          httpTargets.add(`https://${fqdn}`)
          httpTargets.add(`http://${fqdn}`)
        }

        if (httpTargets.size === 0) return 0

        const urlFile = path.join(TMP_DIR, `httpx_input_${runId}.txt`)
        fs.writeFileSync(urlFile, [...httpTargets].join('\n'))

        const lines = await _runTool('httpx', [
          '-l', urlFile,
          '-json', '-silent',
          '-title', '-tech-detect', '-web-server',
          '-tls-grab', '-status-code',
          '-timeout', '10',
          '-threads', '20',
        ], log)

        let count = 0
        for (const line of lines) {
          try {
            const obj = JSON.parse(line)
            const url  = obj.url  || obj.input
            const ip   = obj.host || obj['a'] || null
            const port = obj.port ? parseInt(obj.port) : (url.startsWith('https') ? 443 : 80)
            const fqdn = obj.input ? new URL(obj.input).hostname : null
            const tech = obj.tech ? JSON.stringify(obj.tech) : null

            asmDb.prepare(`
              INSERT INTO raw_httpx
                (job_id, url, fqdn, ip, port, status_code, title, web_server,
                 content_length, content_type, technology, tls_version, tls_cipher,
                 response_time_ms, raw_json)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              runId, url, fqdn, ip, port,
              obj.status_code || null,
              obj.title || null,
              obj.webserver || null,
              obj.content_length || null,
              obj['content-type'] || null,
              tech,
              obj.tls ? obj.tls.version : null,
              obj.tls ? obj.tls.cipher  : null,
              obj.time ? Math.round(parseFloat(obj.time) * 1000) : null,
              JSON.stringify(obj)
            )

            // http_endpoint 정규화
            if (url && obj.status_code) {
              _upsertHttpEndpoint(url, fqdn, ip, port, obj)
            }
            count++
          } catch {}
        }
        try { fs.unlinkSync(urlFile) } catch {}
        return count
      })
    } else {
      _skipStage(runId, 'httpx', '취소됨')
    }
    stagesDone++
    _updateProgress(runId, stagesDone, 'nuclei')

    // ══ 중간 집계: asset_current 갱신 ═══════════════════════════
    if (!_cancelRequested) {
      console.log('[SCANNER] asset_current 집계 갱신 중…')
      refreshAssetCurrent()
    }

    // ══ Stage 8: Nuclei — 취약점 스캔 ═══════════════════════════
    // asset_current의 실제 IP 목록 대상으로 실행
    if (!_cancelRequested) {
      await _runStage(runId, 'nuclei', async (log) => {
        const assetRows = asmDb.prepare(
          "SELECT ip, open_ports, fqdns FROM asset_current WHERE status='active'"
        ).all()

        if (assetRows.length === 0) return 0

        // 스캔 대상 URL 목록 구성 (IP:Port + FQDN)
        const nucleiTargets = new Set()
        for (const row of assetRows) {
          const ports = _parseJSON(row.open_ports, [])
          const fqdns = _parseJSON(row.fqdns, [])
          const WEB_PORTS = [80, 443, 8080, 8443, 8888, 3000, 5000]
          for (const port of ports) {
            if (WEB_PORTS.includes(port)) {
              const scheme = (port === 443 || port === 8443) ? 'https' : 'http'
              nucleiTargets.add(`${scheme}://${row.ip}:${port}`)
            }
          }
          for (const fqdn of fqdns) {
            nucleiTargets.add(`https://${fqdn}`)
          }
          // IP 자체도 추가 (네트워크 레벨 취약점)
          nucleiTargets.add(row.ip)
        }

        if (nucleiTargets.size === 0) return 0

        const targetFile = path.join(TMP_DIR, `nuclei_input_${runId}.txt`)
        fs.writeFileSync(targetFile, [...nucleiTargets].join('\n'))

        const lines = await _runTool('nuclei', [
          '-l', targetFile,
          '-json-export', '-',
          '-severity', 'critical,high,medium,low',
          '-silent',
          '-rate-limit', '50',
          '-concurrency', '10',
          '-timeout', '10',
          '-no-interactsh',
        ], log, { timeout: 8 * 60 * 1000 })

        let count = 0
        for (const line of lines) {
          try {
            const obj = JSON.parse(line)
            const targetUrl  = obj.matched_at || obj.host || ''
            const templateId = obj['template-id'] || obj.templateID || ''
            const severity   = (obj.info && obj.info.severity) || 'info'
            const cve        = obj.info && obj.info.classification
                             ? (obj.info.classification['cve-id'] || [])[0] || null
                             : null
            const cvss       = obj.info && obj.info.classification
                             ? obj.info.classification['cvss-score'] || null
                             : null

            // IP 추출
            let targetIp = null, targetFqdn = null, targetPort = null
            try {
              const u = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`)
              const h = u.hostname
              if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) targetIp = h
              else { targetFqdn = h; targetIp = _lookupIpForFqdn(h) }
              targetPort = u.port ? parseInt(u.port) : (u.protocol === 'https:' ? 443 : 80)
            } catch {}

            asmDb.prepare(`
              INSERT INTO raw_nuclei
                (job_id, template_id, template_name, severity, cvss_score, cve_id,
                 tags, target_url, target_ip, target_fqdn, target_port, matched_at,
                 extracted_results, raw_json)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).run(
              runId, templateId,
              (obj.info && obj.info.name) || templateId,
              severity,
              cvss ? parseFloat(cvss) : null,
              cve, null,
              targetUrl, targetIp, targetFqdn, targetPort,
              obj.matched_at || targetUrl,
              obj['extracted-results'] ? JSON.stringify(obj['extracted-results']) : null,
              JSON.stringify(obj)
            )

            // vulnerability_finding 정규화
            _upsertVulnerabilityFinding({
              ip: targetIp, fqdn: targetFqdn, url: targetUrl,
              port: targetPort, template_id: templateId,
              template_name: (obj.info && obj.info.name) || templateId,
              severity, cvss_score: cvss ? parseFloat(cvss) : null,
              cve_id: cve, matched_at: obj.matched_at || targetUrl,
              tags: obj.info && obj.info.tags ? obj.info.tags.join(',') : null,
            })
            count++
          } catch {}
        }
        try { fs.unlinkSync(targetFile) } catch {}

        // Nuclei 후 asset_current 재집계 (위험도 업데이트)
        refreshAssetCurrent()
        return count
      })
    } else {
      _skipStage(runId, 'nuclei', '취소됨')
    }
    stagesDone++

    // ══ 완료 ════════════════════════════════════════════════════
    const summary = _buildSummary(runId)
    asmDb.prepare(`
      UPDATE pipeline_run
      SET status='done', finished_at=datetime('now','localtime'),
          done_stages=?, current_stage=NULL, summary_json=?
      WHERE id=?
    `).run(stagesDone, JSON.stringify(summary), runId)

    console.log(`[SCANNER] 파이프라인 ${runId} 완료:`, summary)

  } catch (err) {
    _finishPipeline(runId, 'failed', err.message)
    throw err
  } finally {
    _runningPipelineId = null
    _cancelRequested   = false
  }
}

// ─── 스테이지 실행 래퍼 ───────────────────────────────────────

async function _runStage(runId, stage, fn) {
  const stageId = asmDb.prepare(`
    INSERT INTO pipeline_stage_log (run_id, stage, status, started_at)
    VALUES (?, ?, 'running', datetime('now','localtime'))
  `).run(runId, stage).lastInsertRowid

  asmDb.prepare(`UPDATE pipeline_run SET current_stage=? WHERE id=?`).run(stage, runId)

  console.log(`[SCANNER] Stage[${stage}] 시작`)

  let resultCount = 0
  try {
    // fn은 (log) => Promise<number> 형태
    // log: (cmdLine) => void
    resultCount = await fn((cmd) => {
      asmDb.prepare(`UPDATE pipeline_stage_log SET command_line=? WHERE id=?`).run(cmd, stageId)
    }) || 0

    asmDb.prepare(`
      UPDATE pipeline_stage_log
      SET status='done', finished_at=datetime('now','localtime'), result_count=?
      WHERE id=?
    `).run(resultCount, stageId)
    console.log(`[SCANNER] Stage[${stage}] 완료 — ${resultCount}건`)

  } catch (err) {
    asmDb.prepare(`
      UPDATE pipeline_stage_log
      SET status='failed', finished_at=datetime('now','localtime'), error_msg=?
      WHERE id=?
    `).run(err.message, stageId)
    console.error(`[SCANNER] Stage[${stage}] 오류:`, err.message)
    // 단계 실패는 치명적이지 않음 — 다음 단계 계속
  }
}

function _skipStage(runId, stage, reason) {
  asmDb.prepare(`
    INSERT INTO pipeline_stage_log (run_id, stage, status, started_at, finished_at, error_msg)
    VALUES (?, ?, 'skipped', datetime('now','localtime'), datetime('now','localtime'), ?)
  `).run(runId, stage, reason)
  console.log(`[SCANNER] Stage[${stage}] 건너뜀 — ${reason}`)
}

function _updateProgress(runId, done, current) {
  asmDb.prepare(`
    UPDATE pipeline_run SET done_stages=?, current_stage=? WHERE id=?
  `).run(done, current, runId)
}

function _finishPipeline(runId, status, errMsg) {
  asmDb.prepare(`
    UPDATE pipeline_run
    SET status=?, finished_at=datetime('now','localtime'), error_msg=?
    WHERE id=?
  `).run(status, errMsg || null, runId)
  _runningPipelineId = null
  _cancelRequested   = false
}

// ─── 툴 실행 헬퍼 ─────────────────────────────────────────────

/**
 * 외부 커맨드를 실행하고 stdout 줄 목록을 반환
 */
function _runTool(cmd, args, logFn, opts = {}) {
  const timeout = opts.timeout || TOOL_TIMEOUT_MS
  const resolvedCmd = _resolveTool(cmd)
  const cmdLine = `${resolvedCmd} ${args.join(' ')}`
  if (logFn) logFn(cmdLine)
  console.log(`[TOOL] ${cmdLine}`)

  return new Promise((resolve) => {
    const lines = []
    const errBuf = []
    const proc = spawn(resolvedCmd, args, {
      env: { ...process.env, HOME: process.env.HOME || '/root' },
      stdio: ['ignore', 'pipe', 'pipe']
    })

    let buf = ''
    proc.stdout.on('data', (chunk) => {
      buf += chunk.toString()
      const parts = buf.split('\n')
      buf = parts.pop()
      for (const l of parts) {
        const t = l.trim()
        if (t) lines.push(t)
      }
    })

    proc.stderr.on('data', (chunk) => {
      errBuf.push(chunk.toString())
    })

    const timer = setTimeout(() => {
      console.warn(`[TOOL] ${resolvedCmd} 타임아웃 — 강제 종료`)
      proc.kill('SIGKILL')
    }, timeout)

    proc.on('close', (code) => {
      clearTimeout(timer)
      if (buf.trim()) lines.push(buf.trim())
      if (code !== 0 && code !== null) {
        console.warn(`[TOOL] ${resolvedCmd} 종료코드=${code}: ${errBuf.slice(-3).join(' ').slice(0,200)}`)
      }
      // 오류가 있어도 수집된 lines를 반환 (부분 결과)
      resolve(lines)
    })

    proc.on('error', (err) => {
      clearTimeout(timer)
      console.error(`[TOOL] ${resolvedCmd} 실행 오류:`, err.message)
      resolve(lines)
    })
  })
}

// ─── Normalized Zone upsert 헬퍼 ─────────────────────────────

function _upsertAssetAndName(ip, fqdn, recordType, source) {
  // asset upsert
  asmDb.prepare(`
    INSERT INTO asset (ip, is_exposed, first_seen, last_seen)
    VALUES (?, 1, datetime('now','localtime'), datetime('now','localtime'))
    ON CONFLICT(ip) DO UPDATE SET last_seen=datetime('now','localtime')
  `).run(ip)

  // asset_name upsert
  const rootDomain = fqdn.split('.').slice(-2).join('.')
  asmDb.prepare(`
    INSERT INTO asset_name (asset_id, fqdn, root_domain, record_type, source, first_seen, last_seen)
    SELECT id, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime')
    FROM asset WHERE ip=?
    ON CONFLICT(asset_id, fqdn) DO UPDATE SET last_seen=datetime('now','localtime'), source=excluded.source
  `).run(fqdn, rootDomain, recordType, source, ip)
}

function _upsertNetworkService(ip, port, protocol, state, serviceName, product, version, src) {
  // asset 없으면 먼저 생성
  asmDb.prepare(`
    INSERT INTO asset (ip, is_exposed, first_seen, last_seen)
    VALUES (?, 1, datetime('now','localtime'), datetime('now','localtime'))
    ON CONFLICT(ip) DO UPDATE SET last_seen=datetime('now','localtime')
  `).run(ip)

  asmDb.prepare(`
    INSERT INTO network_service
      (asset_id, ip, port, protocol, state, service_name, product, version, fingerprint_source, first_seen, last_seen)
    SELECT a.id, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime')
    FROM asset a WHERE a.ip=?
    ON CONFLICT(ip, port, protocol) DO UPDATE SET
      state=excluded.state,
      service_name=COALESCE(excluded.service_name, service_name),
      product=COALESCE(excluded.product, product),
      version=COALESCE(excluded.version, version),
      fingerprint_source=excluded.fingerprint_source,
      last_seen=datetime('now','localtime')
  `).run(ip, port, protocol||'tcp', state||'open', serviceName||null, product||null, version||null, src||'nmap', ip)
}

function _upsertHttpEndpoint(url, fqdn, ip, port, obj) {
  if (ip) {
    asmDb.prepare(`
      INSERT INTO asset (ip, is_exposed, first_seen, last_seen)
      VALUES (?, 1, datetime('now','localtime'), datetime('now','localtime'))
      ON CONFLICT(ip) DO UPDATE SET last_seen=datetime('now','localtime')
    `).run(ip)
  }

  const tech = obj.tech ? JSON.stringify(obj.tech) : null
  asmDb.prepare(`
    INSERT INTO http_endpoint
      (asset_id, url, fqdn, ip, port, scheme, status_code, title, web_server, technology,
       tls_version, response_time_ms, first_seen, last_seen)
    SELECT a.id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now','localtime'), datetime('now','localtime')
    FROM asset a WHERE a.ip=?
    ON CONFLICT(url) DO UPDATE SET
      status_code=excluded.status_code, title=excluded.title,
      web_server=excluded.web_server, technology=excluded.technology,
      tls_version=excluded.tls_version, response_time_ms=excluded.response_time_ms,
      last_seen=datetime('now','localtime')
  `).run(
    url, fqdn, ip, port,
    url.startsWith('https') ? 'https' : 'http',
    obj.status_code || null, obj.title || null,
    obj.webserver || null, tech,
    obj.tls ? obj.tls.version : null,
    obj.time ? Math.round(parseFloat(obj.time) * 1000) : null,
    ip
  )
}

function _upsertVulnerabilityFinding({ ip, fqdn, url, port, service_name, template_id, template_name, severity, cvss_score, cve_id, matched_at, tags }) {
  if (!template_id) return
  if (ip) {
    asmDb.prepare(`
      INSERT INTO asset (ip, is_exposed, first_seen, last_seen)
      VALUES (?, 1, datetime('now','localtime'), datetime('now','localtime'))
      ON CONFLICT(ip) DO UPDATE SET last_seen=datetime('now','localtime')
    `).run(ip)
  }
  asmDb.prepare(`
    INSERT INTO vulnerability_finding
      (asset_id, ip, fqdn, url, port, service_name, template_id, template_name,
       severity, cvss_score, cve_id, tags, matched_at, status, first_seen, last_seen)
    SELECT a.id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open',
           datetime('now','localtime'), datetime('now','localtime')
    FROM asset a WHERE a.ip=?
    ON CONFLICT DO NOTHING
  `).run(ip, fqdn||null, url||null, port||null, service_name||null,
    template_id, template_name||template_id, severity||'info',
    cvss_score||null, cve_id||null, tags||null, matched_at||null, ip)
}

function _lookupIpForFqdn(fqdn) {
  const row = asmDb.prepare('SELECT ip FROM asset_name an JOIN asset a ON a.id=an.asset_id WHERE an.fqdn=? LIMIT 1').get(fqdn)
  return row ? row.ip : null
}

function _buildSummary(runId) {
  // 이번 run에서 수집된 결과 집계
  const stages = asmDb.prepare('SELECT stage, status, result_count FROM pipeline_stage_log WHERE run_id=?').all(runId)
  const newAssets = asmDb.prepare("SELECT COUNT(*) AS c FROM asset WHERE first_seen >= (SELECT started_at FROM pipeline_run WHERE id=?)").get(runId).c
  const newVulns  = asmDb.prepare("SELECT COUNT(*) AS c FROM vulnerability_finding WHERE first_seen >= (SELECT started_at FROM pipeline_run WHERE id=?)").get(runId).c
  const stageMap = {}
  stages.forEach(s => { stageMap[s.stage] = { status: s.status, count: s.result_count } })
  return { new_assets: newAssets, new_vulns: newVulns, stages: stageMap }
}

function _parseJSON(str, fallback) {
  if (!str) return fallback
  try { return JSON.parse(str) } catch { return fallback }
}

module.exports = { startPipeline, cancelPipeline, getRunningPipelineId }
