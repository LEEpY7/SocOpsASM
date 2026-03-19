'use strict'

const PgNative = require('pg-native')

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
    const rows = this.db.client.querySync(sql, values)
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
    const rows = this.db.client.querySync(sql, values)
    return {
      changes: Array.isArray(rows) ? rows.length : 0,
      lastInsertRowid: rows && rows[0] && rows[0].id ? rows[0].id : undefined
    }
  }
}

class PgCompatDatabase {
  constructor() {
    this.client = new PgNative()
    this.client.connectSync(buildConnectionString())
  }

  pragma() {}

  exec(sql) {
    const statements = splitSqlStatements(sql)
    for (const stmt of statements) {
      this.client.querySync(stmt)
    }
  }

  prepare(sql) {
    return new Statement(this, sql)
  }

  transaction(fn) {
    return (...args) => {
      this.client.querySync('BEGIN')
      try {
        const ret = fn(...args)
        this.client.querySync('COMMIT')
        return ret
      } catch (e) {
        this.client.querySync('ROLLBACK')
        throw e
      }
    }
  }
}

module.exports = PgCompatDatabase
