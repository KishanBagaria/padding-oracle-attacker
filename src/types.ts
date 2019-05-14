export interface HeadersObject { [key: string]: string }
export interface OracleResult { url: string, statusCode: number, headers: HeadersObject, body: string }

interface RequestOptions {
  method?: string
  headers?: string | string[] | HeadersObject
  data?: string
}
interface OptionsBase {
  url: string
  blockSize: number
  isDecryptionSuccess: (oracleResult: OracleResult) => boolean
  requestOptions?: RequestOptions
  concurrency?: number
  transformPayload?: (payload: Buffer) => string
  logMode?: 'full' | 'minimal' | 'none'
  isCacheEnabled?: boolean
}
export interface POOptions extends OptionsBase {
  ciphertext: Buffer
  plaintext: Buffer
  blockCount: number
  origBytes: Buffer
  foundBytes: Buffer
  interBytes: Buffer
  foundOffsets: Set<number>
  initFirstPayloadBlockWithOrigBytes?: boolean
  startFromFirstBlock?: boolean
}
export interface DecryptOptions extends OptionsBase {
  ciphertext: Buffer
  makeInitialRequest?: boolean
  alreadyFound?: Buffer
  initFirstPayloadBlockWithOrigBytes?: boolean
  startFromFirstBlock?: boolean
}
export interface EncryptOptions extends OptionsBase {
  plaintext: Buffer
  makeFinalRequest?: boolean
  lastCiphertextBlock?: Buffer
}
