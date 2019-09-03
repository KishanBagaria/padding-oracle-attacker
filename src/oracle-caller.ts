import got from 'got'
import ow from 'ow'
import { pick } from 'lodash'

import cacheStore from './cache'
import { arrayifyHeaders } from './util'
import { DEFAULT_USER_AGENT } from './constants'
import { HeadersObject, OracleResult, OracleCallerOptions } from './types'

type AddPayload = (str?: string) => string | undefined

function getHeaders(headersArg: string | string[] | HeadersObject | undefined, addPayload: AddPayload) {
  if (!headersArg) return {}
  const headersArr = (() => {
    if (Array.isArray(headersArg)) return headersArg
    if (typeof headersArg === 'object') return arrayifyHeaders(headersArg)
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

const OracleCaller = (options: OracleCallerOptions) => {
  const {
    url: _url,
    requestOptions = {},
    transformPayload,
    isCacheEnabled = true
  } = options
  ow(_url, 'url', ow.string)
  if (transformPayload) ow(transformPayload, ow.function)
  ow(requestOptions, ow.object)
  ow(requestOptions.method, ow.optional.string)
  if (requestOptions.headers) ow(requestOptions.headers, ow.any(ow.object, ow.string, ow.array))
  ow(requestOptions.data, ow.optional.string)

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
    networkStats.lastDownloadTime = response.timings.phases.total
    networkStats.bytesDown += response.socket.bytesRead || 0
    networkStats.bytesUp += response.socket.bytesWritten || 0
    const result = pick(response, ['statusCode', 'headers', 'body']) as OracleResult
    if (isCacheEnabled) await cacheStore.set(cacheKey, result)
    return { url, ...result }
  }
  return { networkStats, callOracle }
}

export default OracleCaller
