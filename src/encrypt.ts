import ow from 'ow'

import { addPadding } from './util'
import { encryption } from './logging'
import PaddingOracle from './padding-oracle'
import { EncryptOptions } from './types'

const { logStart, logCompletion } = encryption

async function encrypt({ url, blockSize, logMode = 'full', plaintext: _plaintext, makeFinalRequest = true, lastCiphertextBlock, ...args }: EncryptOptions) {
  ow(_plaintext, 'plaintext', ow.buffer)
  ow(lastCiphertextBlock, ow.optional.buffer)
  if (lastCiphertextBlock && lastCiphertextBlock.length !== blockSize) throw TypeError('Invalid `lastCiphertextBlock`, should have length equal to `blockSize`')

  const plaintext = addPadding(_plaintext, blockSize)

  const blockCount = (plaintext.length / blockSize) + 1
  const totalSize = blockCount * blockSize

  const foundBytes = Buffer.alloc(totalSize) // ciphertext bytes
  const interBytes = Buffer.alloc(totalSize - blockSize)
  const foundOffsets = new Set()

  if (lastCiphertextBlock) {
    lastCiphertextBlock.copy(foundBytes, foundBytes.length - blockSize)
  }

  if (['full', 'minimal'].includes(logMode)) logStart({ blockCount, totalSize })

  const po = PaddingOracle({
    origBytes: plaintext, ciphertext: foundBytes, plaintext, foundBytes, interBytes, foundOffsets, blockSize, blockCount, url, logMode, ...args
  })
  await po.processBlocks()
  const finalRequest = makeFinalRequest ? await po.callOracle(foundBytes) : undefined

  if (['full', 'minimal'].includes(logMode)) logCompletion({ foundBytes, interBytes, finalRequest })

  return { blockCount, totalSize, foundBytes, interBytes, finalRequest }
}

export default encrypt
