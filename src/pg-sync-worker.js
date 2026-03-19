'use strict'

const fs = require('fs')
const { parentPort, workerData } = require('worker_threads')
const { Client } = require('pg')

const client = new Client({ connectionString: workerData.connectionString })
const ready = client.connect()

parentPort.on('message', async ({ sql, values, resultFile, signal }) => {
  const view = new Int32Array(signal)

  try {
    await ready
    const result = await client.query(sql, values)
    fs.writeFileSync(resultFile, JSON.stringify({
      result: {
        rows: result.rows,
        rowCount: result.rowCount
      }
    }))
  } catch (error) {
    fs.writeFileSync(resultFile, JSON.stringify({
      error: {
        message: error.message,
        code: error.code,
        detail: error.detail,
        constraint: error.constraint
      }
    }))
  } finally {
    Atomics.store(view, 0, 1)
    Atomics.notify(view, 0, 1)
  }
})
