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

function normalizeSql(sql) {
  let out = sql
  out = out.replace(/INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT/gi, 'BIGSERIAL PRIMARY KEY')
  out = out.replace(/\bINSERT\s+OR\s+IGNORE\s+INTO\b/gi, 'INSERT INTO')

  // SQLite datetime 호환 표현을 PostgreSQL 함수 호출로 정규화
  out = out.replace(/datetime\(\s*'now'\s*,\s*'localtime'\s*\)/gi, 'datetime(\'now\',\'localtime\')')
  out = out.replace(/datetime\(\s*'now'\s*,\s*'localtime'\s*,\s*([^\)]+)\)/gi, "datetime('now','localtime',$1)")

  return out
}

function compileSqlAndParams(sql, params) {
  const values = []
  let idx = 1

  const isArray = Array.isArray(params)
  const isObject = params && typeof params === 'object' && !isArray

  if (!isArray && !isObject && params !== undefined) params = [params]

  const compiled = sql.replace(/\?|@[A-Za-z_][A-Za-z0-9_]*/g, (token) => {
    if (token === '?') {
      const arr = Array.isArray(params) ? params : []
      values.push(arr.shift())
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
    this.sql = normalizeSql(sql)
  }

  _query(params, expect = 'all') {
    const { sql, values } = compileSqlAndParams(this.sql, params)
    const rows = this.db.client.querySync(sql, values)
    if (expect === 'get') return rows[0]
    return rows
  }

  all(params) {
    return this._query(params, 'all')
  }

  get(params) {
    return this._query(params, 'get')
  }

  run(params) {
    const { sql, values } = compileSqlAndParams(this.sql, params)
    const isInsert = /^\s*insert\b/i.test(sql)
    const hasReturning = /\breturning\b/i.test(sql)

    let finalSql = sql
    if (isInsert && !hasReturning) {
      if (/\bon\s+conflict\b/i.test(finalSql)) {
        // keep as-is
      } else {
        finalSql += ' ON CONFLICT DO NOTHING'
      }
      finalSql += ' RETURNING id'
    }

    const rows = this.db.client.querySync(finalSql, values)
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
    this._initCompatibilityFunctions()
  }

  _initCompatibilityFunctions() {
    this.client.querySync(`
      CREATE OR REPLACE FUNCTION datetime(base TEXT, mode TEXT)
      RETURNS TEXT AS $$
      BEGIN
        IF base = 'now' AND mode = 'localtime' THEN
          RETURN to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS');
        END IF;
        RETURN to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS');
      END;
      $$ LANGUAGE plpgsql;

      CREATE OR REPLACE FUNCTION datetime(base TEXT, mode TEXT, mod TEXT)
      RETURNS TEXT AS $$
      DECLARE
        ts TIMESTAMP;
      BEGIN
        ts := NOW();
        IF mod LIKE '%days' THEN
          ts := ts + (replace(mod, ' days', '')::TEXT || ' days')::INTERVAL;
        ELSIF mod LIKE '%hours' THEN
          ts := ts + (replace(mod, ' hours', '')::TEXT || ' hours')::INTERVAL;
        END IF;
        RETURN to_char(ts, 'YYYY-MM-DD HH24:MI:SS');
      END;
      $$ LANGUAGE plpgsql;
    `)
  }

  pragma() {}

  exec(sql) {
    const statements = splitSqlStatements(normalizeSql(sql))
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
