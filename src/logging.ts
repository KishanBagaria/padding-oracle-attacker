import chalk from 'chalk'
import wrapAnsi from 'wrap-ansi'
import logUpdate from 'log-update'
import ansiStyles from 'ansi-styles'
import prettyBytes from 'pretty-bytes'
import { getPrintable } from './util'
import { HeadersObject, OracleResult } from './types'

const { isTTY } = process.stdout

function getBar(percent: number, barSize: number) {
  const barComplete = '█'.repeat(percent * barSize)
  const barIncomplete = '░'.repeat(barSize - barComplete.length)
  return { barComplete, barIncomplete }
}

interface ColorizeHex {
  cipherHex: string
  totalSize: number
  foundOffsets: Set<number>
  currentByteColor: string
  currentByteHex: string
  currentByteOffset: number
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const aStyles = ansiStyles as any
function colorizeHex({ cipherHex, totalSize, foundOffsets, currentByteColor, currentByteHex, currentByteOffset }: ColorizeHex) {
  let result = ''
  let lastColor = ''
  for (let i = 0; i < totalSize; i++) {
    const isCurrentByte = currentByteOffset === i
    let color = 'gray'
    if (isCurrentByte) color = currentByteColor
    else if (foundOffsets.has(i) || i >= (totalSize - 16)) color = 'green'

    const byteHex = cipherHex.slice(i * 2, i * 2 + 2)
    if (lastColor !== color) {
      result += (lastColor ? aStyles[lastColor].close : '') + aStyles[color].open
      lastColor = color
    }
    result += isCurrentByte ? currentByteHex : byteHex
  }
  result += aStyles[lastColor].close
  return result
}

interface LogProgressOptions {
  plaintext: Buffer
  ciphertext: Buffer
  foundOffsets: Set<number>
  blockSize: number
  blockI: number
  byteI: number
  byte: number
  decryptionSuccess: boolean
  networkStats: { count: number, lastDownloadTime: number, bytesDown: number, bytesUp: number }
  startFromFirstBlock?: boolean
}
export function logProgress(
  { plaintext, ciphertext, foundOffsets, blockSize, blockI, byteI, byte, decryptionSuccess, networkStats, startFromFirstBlock }: LogProgressOptions
) {
  const cipherHex = ciphertext.toString('hex')
  const currentByteHex = byte.toString(16).padStart(2, '0')
  const start = blockSize * blockI
  const grayEnd = 2 * (start + byteI)
  const greenStart = 2 * (start + byteI + 1)
  const currentByteColor = decryptionSuccess ? 'green' : 'yellow'
  const colorized = startFromFirstBlock
    ? colorizeHex({ cipherHex, totalSize: ciphertext.length, foundOffsets, currentByteColor, currentByteHex, currentByteOffset: start + byteI })
    : [
      chalk.gray(cipherHex.slice(0, grayEnd)),
      chalk[currentByteColor](currentByteHex),
      chalk.green(cipherHex.slice(greenStart))
    ].join('')
  const plainUTF8 = plaintext.toString('utf8')
  const plainHex = plaintext.toString('hex')
  const percent = (foundOffsets.size + blockSize) / ciphertext.length
  const mapFunc = (ciphertextBlockHex: string, i: number) => {
    const xStart = (i - 1) * blockSize
    const end = xStart + blockSize
    const hex = plainHex.slice(2 * xStart, 2 * end)
    const plain = getPrintable(plainUTF8.slice(xStart, end))
    return `${(i + 1).toString().padStart(2)}. ${ciphertextBlockHex} ${hex} ${plain}`
  }
  const cipherplain = wrapAnsi(colorized, blockSize * 2, { hard: true })
    .split('\n')
    .map(mapFunc)
    .join('\n')
  const { barComplete, barIncomplete } = getBar(percent, blockSize * 4 + 4)
  const log = isTTY ? logUpdate : console.log
  log(
    cipherplain,
    '\n' + barComplete + barIncomplete, (percent * 100).toFixed(1).padStart(5) + '%', (blockI + 1) + 'x' + (byteI + 1), byte + '/256',
    `\n${networkStats.count.toString().padStart(4)} total network requests | last request took ${networkStats.lastDownloadTime.toString().padStart(4)}ms`,
    `| ${prettyBytes(networkStats.bytesDown).padStart(7)} downloaded | ${prettyBytes(networkStats.bytesUp).padStart(7)} uploaded`
  )
}
export function logWarning(txt: string) {
  logUpdate.done()
  console.error(chalk`
{yellow.underline Warning}: ${txt}
`)
}

const stringifyHeaders = (headers: HeadersObject) => Object.entries(headers).map(([k, v]) => `${chalk.gray(k)}: ${v}`).join('\n')

function logRequest(request: OracleResult, logBody: boolean) {
  console.log(request.statusCode, request.url)
  console.log(stringifyHeaders(request.headers))
  if (logBody) {
    console.log()
    console.log(request.body)
  }
}

interface LogStart { blockCount: number, totalSize: number, initialRequest?: Promise<OracleResult>, decryptionSuccess?: Promise<boolean> }
export const decryption = {
  async logStart({ blockCount, totalSize, initialRequest: _initialRequest, decryptionSuccess }: LogStart) {
    console.log(chalk.bold('~~~DECRYPTING~~~'))
    console.log('total bytes:', chalk.yellow(String(totalSize)), '|', 'blocks:', chalk.yellow(String(blockCount - 1)))
    console.log()
    console.log('---making request with original ciphertext---')
    const initialRequest = await _initialRequest
    if (initialRequest) {
      if (!await decryptionSuccess) {
        logWarning(`Decryption failed for initial request with original ciphertext.
        The error string (or isDecryptionSuccess() parameter) you provided for determining decryption success seems to be incorrect.`)
      }
      logRequest(initialRequest, initialRequest.body.length < 1024)
    }
    console.log()
  },
  logCompletion({ foundBytes, interBytes }: { foundBytes: Buffer, interBytes: Buffer }) {
    logUpdate.done()
    console.log()
    console.log('---plaintext printable bytes in utf8---')
    console.log(getPrintable(foundBytes.toString('utf8')))
    console.log()
    console.log('---plaintext bytes in hex---')
    console.log(foundBytes.toString('hex'))
    console.log()
    console.log('---intermediate bytes in hex---')
    console.log(interBytes.toString('hex'))
    console.log()
  }
}
export const encryption = {
  logStart({ blockCount, totalSize }: LogStart) {
    console.log(chalk.bold('~~~ENCRYPTING~~~'))
    console.log('total bytes:', chalk.yellow(String(totalSize)), '|', 'blocks:', chalk.yellow(String(blockCount - 1)))
    console.log()
  },
  logCompletion({ foundBytes, interBytes, finalRequest }: { foundBytes: Buffer, interBytes: Buffer, finalRequest?: OracleResult }) {
    logUpdate.done()
    console.log()
    console.log('---ciphertext bytes in hex---')
    console.log(foundBytes.toString('hex'))
    console.log()
    console.log('---intermediate bytes in hex---')
    console.log(interBytes.toString('hex'))
    console.log()
    if (!finalRequest) return
    console.log('---final http request---')
    logRequest(finalRequest, true)
    console.log()
  }
}

export function logError(err: Error) {
  logUpdate.done()
  console.error(chalk.red(err.stack || err.message))
}
