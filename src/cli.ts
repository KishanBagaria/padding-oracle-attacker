import minimist from 'minimist'
import chalk from 'chalk'

import decryptFunc from './decrypt'
import encryptFunc from './encrypt'
import { logError } from './logging'
import { OracleResult } from './types'
import { PKG_NAME, PKG_VERSION } from './constants'

const hexToBuffer = (str: string) => Buffer.from(str.replace(/\s+/g, ''), 'hex')

const argv = minimist(process.argv.slice(2), {
  string: ['method', 'header', 'data', 'payload-encoding'],
  boolean: ['version', 'disable-cache'],
  alias: {
    v: 'version',
    c: 'concurrency',
    X: 'method',
    H: 'header',
    d: 'data',
    e: 'payload-encoding',
    'start-from-first-block': 'start-from-1st-block'
  }
})

const USAGE = chalk`
  {inverse Usage}
    {gray $} padding-oracle-attacker decrypt <url> hex:<ciphertext_hex> <block_size> <error> [options]

    {gray $} padding-oracle-attacker encrypt <url> <plaintext>          <block_size> <error> [options]
    {gray $} padding-oracle-attacker encrypt <url> hex:<plaintext_hex>  <block_size> <error> [options]

  {inverse Commands}
    decrypt                 Finds the plaintext (foobar) for given ciphertext (hex:0123abcd)
    encrypt                 Finds the ciphertext (hex:abcd1234) for given plaintext (foo=bar)

  {inverse Arguments}
    <url>                   URL to attack. Payload will be inserted at the end by default. To specify
                            a custom injection point, include {underline \{POPAYLOAD\}} in a header (-H),
                            request body (-d) or the URL
    <block_size>            Block size used by the encryption algorithm on the server
    <error>                 The string present in response when decryption fails on the server.
                            Specify a string present in the HTTP response body (like PaddingException)
                            or status code of the HTTP response (like 400)

  {inverse Options}
    -c, --concurrency       Requests to be sent concurrently                      [default: 128]
        --disable-cache     Disable network cache. Saved to                       [default: false]
                            poattack-cache.json.gz.txt by default
    -X, --method            HTTP method to use while making request               [default: GET]
    -H, --header            Headers to be sent with request.
                              -H 'Cookie: cookie1' -H 'User-Agent: Googlebot/2.1'
    -d, --data              Request body
                              JSON string: \{"id": 101, "foo": "bar"\}
                              URL encoded: id=101&foo=bar
                            Make sure to specify the Content-Type header.

    -e, --payload-encoding  Ciphertext payload encoding for {underline \{POPAYLOAD\}}           [default: hex]
                              base64          FooBar+/=
                              base64-urlsafe  FooBar-_
                              hex             deadbeef
                              hex-uppercase   DEADBEEF
                              base64(xyz)     Custom base64 ('xyz' represent characters for '+/=')

    --start-from-1st-block  Start processing from the first block instead         [default: false]
                            of the last (only works with decrypt mode)

  {inverse Examples}
    {gray $} poattack decrypt http://localhost:2020/decrypt?ciphertext=
        hex:e3e70d8599206647dbc96952aaa209d75b4e3c494842aa1aa8931f51505df2a8a184e99501914312e2c50320835404e9 16 400
    {gray $} poattack encrypt http://localhost:2020/decrypt?ciphertext= "foo bar 🦄" 16 400
    {gray $} poattack encrypt http://localhost:2020/decrypt?ciphertext= hex:666f6f2062617220f09fa684 16 400
  
  {inverse Aliases}
    poattack
    padding-oracle-attack
`

const {
  version, method, H: headers, data, concurrency, e: payloadEncoding = 'hex', 'disable-cache': disableCache, cache, 'start-from-1st-block': startFromFirstBlock
} = argv

const VALID_ENCODINGS = ['hex-uppercase', 'base64', 'base64-urlsafe', 'hex']
async function main() {
  const [operation, url, _cipherOrPlaintext] = argv._
  const [,,, _blockSize = 16] = argv._ as unknown[] as number[]
  const [,,,, paddingError] = argv._ as string[]|number[]
  const blockSize = Math.abs(_blockSize)
  if (version) {
    console.log(PKG_NAME, 'v' + PKG_VERSION)
    return
  }
  const isEncrypt = operation === 'encrypt'
  const isDecrypt = operation === 'decrypt'
  const requestOptions = { method, headers, data }
  if (
    (!isEncrypt && !isDecrypt) || !url || !_cipherOrPlaintext || !blockSize || !paddingError
    || Array.isArray(method) || Array.isArray(concurrency) || Array.isArray(data)
  ) {
    console.error(USAGE)
    return
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    console.error(chalk`{red Invalid argument:} <url>\nMust start with http: or https:`)
    return
  }
  if (blockSize < 1) {
    console.error(chalk`{red Invalid argument:} <block_size>`)
    return
  }
  if (!isNaN(paddingError as number) && (paddingError < 100 || paddingError > 599)) {
    console.error(chalk`{red Invalid option:} --error\nNot a valid status code`)
    return
  }
  if (!VALID_ENCODINGS.includes(payloadEncoding) && !payloadEncoding.startsWith('base64(')) {
    console.error(chalk`
{yellow.underline Warning}: ${payloadEncoding} is unrecognized. Defaulting to hex.
`)
  }
  if (isEncrypt && startFromFirstBlock) {
    console.error(chalk`
{yellow.underline Warning}: Can only start from first block while decrypting.
`)
  }
  if (data && !String(headers).toLowerCase().includes('content-type:')) {
    console.error(chalk`
{yellow.underline Warning}: \`--data\` argument is present without a \`Content-Type\` header.
You may want to set it to {inverse application/x-www-form-urlencoded} or {inverse application/json}
`)
  }
  const isDecryptionSuccess = ({ statusCode, body }: OracleResult) => {
    if (!isNaN(paddingError as number)) return statusCode !== +paddingError
    return !body.includes(paddingError as unknown as string)
  }
  const transformPayload = (payload: Buffer) => {
    if (payloadEncoding === 'hex-uppercase') return payload.toString('hex').toUpperCase()
    if (payloadEncoding === 'base64') return payload.toString('base64')
    if (payloadEncoding === 'base64-urlsafe') return payload.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    if (payloadEncoding.startsWith('base64(')) {
      // base64 with custom alphabet. like "base64(-!~)"
      const [x, y, z] = payloadEncoding.slice('base64('.length).split('')
      return payload.toString('base64').replace(/\+/g, x).replace(/\//g, y).replace(/=/g, z)
    }
    return payload.toString('hex')
  }
  const isCacheEnabled = !disableCache && cache !== false
  const commonArgs = { url, blockSize, isDecryptionSuccess, transformPayload, concurrency, requestOptions, isCacheEnabled }
  const cipherOrPlaintext = String(_cipherOrPlaintext)
  if (isDecrypt) {
    const bytes = hexToBuffer(cipherOrPlaintext.replace(/^hex:/, ''))
    await decryptFunc({
      ...commonArgs,
      ciphertext: bytes,
      startFromFirstBlock
    })
  } else {
    const bytes = cipherOrPlaintext.startsWith('hex:') ? hexToBuffer(cipherOrPlaintext.slice(4)) : Buffer.from(cipherOrPlaintext, 'utf8')
    await encryptFunc({
      ...commonArgs,
      plaintext: bytes
    })
  }
}

main().catch(logError)
