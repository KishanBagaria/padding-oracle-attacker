export interface HeadersObject {
  [key: string]: string;
}
export interface OracleResult {
  url: string;
  statusCode: number;
  headers: HeadersObject;
  body: string;
}

interface RequestOptions {
  method?: 'get' | 'post' | 'put' | 'patch' | 'head' | 'delete' | 'options' | 'trace' | 'GET' | 'POST' | 'PUT' | 'PATCH' | 'HEAD' | 'DELETE' | 'OPTIONS' | 'TRACE';
  headers?: string | string[] | HeadersObject;
  data?: string;
  userAgent?: string;
  timeout?: number;
  retry?: number;
}
export interface OracleCallerOptions {
  url: string;
  requestOptions?: RequestOptions;
  transformPayload?: (payload: Buffer) => string;
  isCacheEnabled?: boolean;
  logMode?: 'full' | 'minimal' | 'none';
}
interface OptionsBase extends OracleCallerOptions {
  blockSize: number;
  concurrency?: number;
  isDecryptionSuccess: (oracleResult: OracleResult) => boolean;
}
export interface ResponseAnalysisOptions extends OracleCallerOptions {
  blockSize: number;
  concurrency?: number;
  saveResponsesToTmpDir?: boolean;
}
export interface PaddingOracleOptions extends OptionsBase {
  ciphertext: Buffer;
  plaintext: Buffer;
  blockCount: number;
  origBytes: Buffer;
  foundBytes: Buffer;
  interBytes: Buffer;
  foundOffsets: Set<number>;
  initFirstPayloadBlockWithOrigBytes?: boolean;
  startFromFirstBlock?: boolean;
}
export interface DecryptOptions extends OptionsBase {
  ciphertext: Buffer;
  makeInitialRequest?: boolean;
  alreadyFound?: Buffer;
  initFirstPayloadBlockWithOrigBytes?: boolean;
  startFromFirstBlock?: boolean;
}
export interface EncryptOptions extends OptionsBase {
  plaintext: Buffer;
  makeFinalRequest?: boolean;
  lastCiphertextBlock?: Buffer;
}
