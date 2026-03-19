'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const {
  summarizePipelineTargets,
  buildMasscanTargetList,
  evaluateMasscanExecution,
} = require('../src/asm-pipeline-utils')

test('CIDR만 있을 때 pipeline target summary가 cidr-only를 반환한다', () => {
  const summary = summarizePipelineTargets([
    { type: 'ip_range', value: '210.216.157.0/24' },
  ])

  assert.equal(summary.mode, 'cidr-only')
  assert.deepEqual(summary.ipRanges, ['210.216.157.0/24'])
  assert.deepEqual(summary.domains, [])
})

test('도메인만 있을 때 pipeline target summary가 domain-only를 반환한다', () => {
  const summary = summarizePipelineTargets([
    { type: 'domain', value: 'example.com' },
  ])

  assert.equal(summary.mode, 'domain-only')
  assert.deepEqual(summary.ipRanges, [])
  assert.deepEqual(summary.domains, ['example.com'])
})

test('CIDR과 도메인이 함께 있을 때 pipeline target summary가 mixed를 반환한다', () => {
  const summary = summarizePipelineTargets([
    { type: 'ip_range', value: '210.216.157.0/24' },
    { type: 'domain', value: 'example.com' },
  ])

  assert.equal(summary.mode, 'mixed')
  assert.deepEqual(summary.ipRanges, ['210.216.157.0/24'])
  assert.deepEqual(summary.domains, ['example.com'])
})

test('masscan 대상 목록은 discovered IP와 CIDR을 중복 없이 병합한다', () => {
  assert.deepEqual(
    buildMasscanTargetList(['1.1.1.1', '1.1.1.1'], ['210.216.157.0/24']),
    ['1.1.1.1', '210.216.157.0/24']
  )
})

test('linux capability가 있으면 비-root에서도 masscan 실행 가능으로 판단한다', () => {
  const result = evaluateMasscanExecution({
    platform: 'linux',
    uid: 1000,
    capabilityOutput: '/tools/masscan cap_net_raw,cap_net_admin+ep',
  })

  assert.equal(result.canRun, true)
  assert.equal(result.useSudo, false)
})

test('macOS 비-root + sudo 불가 환경이면 masscan skip으로 판단한다', () => {
  const result = evaluateMasscanExecution({
    platform: 'darwin',
    uid: 501,
    allowSudo: false,
    sudoAvailable: false,
  })

  assert.equal(result.canRun, false)
  assert.match(result.reason, /macOS/)
})
