'use strict'

const fs = require('fs')
const os = require('os')
const path = require('path')
const { Worker } = require('worker_threads')

function buildConnectionString() {
  if (process.env.DATABASE_URL) return process.env.DATABASE_URL
  const host = process.env.PGHOST || '127.0.0.1'
  const port = process.env.PGPORT || '5432'
  const user = process.env.PGUSER || 'postgres'
  const password = process.env.PGPASSWORD || 'postgres'
  const database = process.env.PGDATABASE || 'socopsasm'
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${database}`
}

function splitSqlStatements(sql) {
  return sql
    .split(/;\s*(?:\n|$)/g)
    .map(s => s.trim())
    .filter(Boolean)
}

function normalizeParams(args) {
  if (args.length === 0) return undefined
  if (args.length === 1) return args[0]
  return args
}

function compileSqlAndParams(sql, params) {
  const values = []
  let idx = 1

  const isArray = Array.isArray(params)
  const isObject = params && typeof params === 'object' && !isArray
  const positional = isArray
    ? [...params]
    : (!isObject && params !== undefined ? [params] : [])

  const compiled = sql.replace(/\?|@[A-Za-z_][A-Za-z0-9_]*/g, (token) => {
    if (token === '?') {
      values.push(positional.shift())
      return `$${idx++}`
    }

    if (token.startsWith('@')) {
      const key = token.slice(1)
      values.push(isObject ? params[key] : undefined)
      return `$${idx++}`
    }

    return token
  })

  return { sql: compiled, values }
}

class Statement {
  constructor(db, sql) {
    this.db = db
    this.sql = sql
  }

  _query(args, expect = 'all') {
    const params = normalizeParams(args)
    const { sql, values } = compileSqlAndParams(this.sql, params)
    const result = this.db._querySync(sql, values)
    const rows = Array.isArray(result.rows) ? result.rows : []
    if (expect === 'get') return rows[0]
    return rows
  }

  all(...args) {
    return this._query(args, 'all')
  }

  get(...args) {
    return this._query(args, 'get')
  }

  run(...args) {
    const params = normalizeParams(args)
    const { sql, values } = compileSqlAndParams(this.sql, params)
    const result = this.db._querySync(sql, values)
    const rows = Array.isArray(result.rows) ? result.rows : []
    return {
      changes: Number.isInteger(result.rowCount) ? result.rowCount : rows.length,
      lastInsertRowid: rows[0] && rows[0].id ? rows[0].id : undefined
    }
  }
}

class PgCompatDatabase {
  constructor() {
    this.requestId = 0
    this.worker = new Worker(path.join(__dirname, 'pg-sync-worker.js'), {
      workerData: { connectionString: buildConnectionString() }
    })
    this.worker.unref()
  }

  _querySync(sql, values = []) {
    const signal = new Int32Array(new SharedArrayBuffer(4))
    const requestId = ++this.requestId
    const resultFile = path.join(os.tmpdir(), `socopsasm-pg-${process.pid}-${Date.now()}-${requestId}.json`)

    this.worker.postMessage({ requestId, sql, values, resultFile, signal: signal.buffer })
    Atomics.wait(signal, 0, 0)

    const payload = JSON.parse(fs.readFileSync(resultFile, 'utf8'))
    fs.unlinkSync(resultFile)

    if (payload.error) {
      const err = new Error(payload.error.message)
      err.code = payload.error.code
      err.detail = payload.error.detail
      err.constraint = payload.error.constraint
      throw err
    }

    return payload.result
  }

  exec(sql) {
    const statements = splitSqlStatements(sql)
    for (const stmt of statements) {
      this._querySync(stmt)
    }
  }

  prepare(sql) {
    return new Statement(this, sql)
  }

  transaction(fn) {
    return (...args) => {
      this._querySync('BEGIN')
      try {
        const ret = fn(...args)
        this._querySync('COMMIT')
        return ret
      } catch (e) {
        this._querySync('ROLLBACK')
        throw e
      }
    }
  }
}

module.exports = PgCompatDatabase
