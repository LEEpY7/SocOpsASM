'use strict'

function splitTargetsByType(targets = []) {
  const ipRanges = []
  const domains = []

  for (const target of targets) {
    if (!target || !target.value) continue
    if (target.type === 'ip_range') ipRanges.push(target.value)
    if (target.type === 'domain') domains.push(target.value)
  }

  return { ipRanges, domains }
}

function uniqueTargets(values = []) {
  return [...new Set(values.filter(Boolean))]
}

function buildMasscanTargetList(discoveredIps = [], ipRanges = []) {
  return uniqueTargets([...discoveredIps, ...ipRanges])
}

function hasMasscanCapability(capabilityOutput = '') {
  const text = String(capabilityOutput || '').toLowerCase()
  return text.includes('cap_net_raw') || text.includes('cap_net_admin')
}

function evaluateMasscanExecution({
  platform = process.platform,
  uid = typeof process.getuid === 'function' ? process.getuid() : null,
  capabilityOutput = '',
  allowSudo = false,
  sudoAvailable = false,
  mode = 'auto',
} = {}) {
  if (mode === 'disabled') {
    return { canRun: false, useSudo: false, reason: 'ASM_MASSCAN_MODE=disabled 설정으로 Masscan 비활성화됨' }
  }

  if (uid === 0) {
    return { canRun: true, useSudo: false, reason: 'root 권한으로 실행 중' }
  }

  if (platform === 'linux' && hasMasscanCapability(capabilityOutput)) {
    return { canRun: true, useSudo: false, reason: 'masscan 바이너리에 cap_net_raw/cap_net_admin capability 부여됨' }
  }

  if (allowSudo && sudoAvailable) {
    return { canRun: true, useSudo: true, reason: 'sudo -n 사용 가능' }
  }

  const baseReason = platform === 'darwin'
    ? 'macOS에서는 일반적으로 root(sudo)로 masscan 실행이 필요합니다'
    : 'root 또는 cap_net_raw/cap_net_admin capability가 필요합니다'

  if (mode === 'require') {
    return { canRun: false, useSudo: false, reason: `Masscan 실행 필수 모드인데 권한이 부족합니다: ${baseReason}` }
  }

  return { canRun: false, useSudo: false, reason: `권한 부족으로 Masscan 단계를 건너뜁니다: ${baseReason}` }
}

function summarizePipelineTargets(targets = []) {
  const { ipRanges, domains } = splitTargetsByType(targets)
  return {
    ipRanges,
    domains,
    hasIpRanges: ipRanges.length > 0,
    hasDomains: domains.length > 0,
    mode: ipRanges.length && domains.length ? 'mixed'
      : ipRanges.length ? 'cidr-only'
      : domains.length ? 'domain-only'
      : 'empty'
  }
}

module.exports = {
  splitTargetsByType,
  uniqueTargets,
  buildMasscanTargetList,
  hasMasscanCapability,
  evaluateMasscanExecution,
  summarizePipelineTargets,
}
