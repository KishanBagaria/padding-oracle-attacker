import chalk from 'chalk';
import wrapAnsi from 'wrap-ansi';
import logUpdate from 'log-update';
import ansiStyles from 'ansi-styles';
import prettyBytes from 'pretty-bytes';
import { table, getBorderCharacters, TableUserConfig } from 'table';
import { getStatusCodeColor, getPrintable } from './util';
import { HeadersObject, OracleResult } from './types';

const { isTTY } = process.stdout;

function getBar(percent: number, barSize: number) {
  const barComplete = '█'.repeat(percent * barSize);
  const barIncomplete = '░'.repeat(barSize - barComplete.length);
  return { barComplete, barIncomplete };
}

interface ColorizeHex {
  cipherHex: string;
  totalSize: number;
  foundOffsets: Set<number>;
  currentByteColor: string;
  currentByteHex: string;
  currentByteOffset: number;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const aStyles = ansiStyles as any;
function colorizeHex({ cipherHex, totalSize, foundOffsets, currentByteColor, currentByteHex, currentByteOffset }: ColorizeHex) {
  let result = '';
  let lastColor = '';
  for (let i = 0; i < totalSize; i++) {
    const isCurrentByte = currentByteOffset === i;
    let color = 'gray';
    if (isCurrentByte) color = currentByteColor;
    else if (foundOffsets.has(i) || i >= totalSize - 16) color = 'green';

    const byteHex = cipherHex.slice(i * 2, i * 2 + 2);
    if (lastColor !== color) {
      result += (lastColor ? aStyles[lastColor].close : '') + aStyles[color].open;
      lastColor = color;
    }
    result += isCurrentByte ? currentByteHex : byteHex;
  }
  result += aStyles[lastColor].close;
  return result;
}

const log = isTTY ? logUpdate : console.log;
const wrapAndSplit = (text: string, size: number) => wrapAnsi(text, size, { hard: true }).split('\n');

interface NetworkStats {
  count: number;
  lastDownloadTime: number;
  bytesDown: number;
  bytesUp: number;
}
interface LogProgressOptions {
  plaintext: Buffer;
  ciphertext: Buffer;
  foundOffsets: Set<number>;
  blockSize: number;
  blockI: number;
  byteI: number;
  byte: number;
  decryptionSuccess: boolean;
  networkStats: NetworkStats;
  startFromFirstBlock?: boolean;
  isCacheEnabled?: boolean;
}
export function logProgress({ plaintext, ciphertext, foundOffsets, blockSize, blockI, byteI, byte, decryptionSuccess, networkStats, startFromFirstBlock, isCacheEnabled }: LogProgressOptions) {
  const cipherHex = ciphertext.toString('hex');
  const currentByteHex = byte.toString(16).padStart(2, '0');
  const start = blockSize * blockI;
  const grayEnd = 2 * (start + byteI);
  const greenStart = 2 * (start + byteI + 1);
  const currentByteColor = decryptionSuccess ? 'green' : 'yellow';
  const colorized = startFromFirstBlock
    ? colorizeHex({ cipherHex, totalSize: ciphertext.length, foundOffsets, currentByteColor, currentByteHex, currentByteOffset: start + byteI })
    : [chalk.gray(cipherHex.slice(0, grayEnd)), chalk[currentByteColor](currentByteHex), chalk.green(cipherHex.slice(greenStart))].join('');

  const printable = getPrintable(plaintext.toString('utf8'));
  const plainHex = plaintext.toString('hex');
  const plainHexColorized = chalk.gray(plainHex.slice(0, grayEnd)) + plainHex.slice(grayEnd);
  const plainHexSplit = wrapAndSplit(plainHexColorized, blockSize * 2);

  const percent = (foundOffsets.size + blockSize) / ciphertext.length;
  const mapFunc = (ciphertextBlockHex: string, i: number) => {
    const xStart = (i - 1) * blockSize;
    const plain = printable.slice(xStart, xStart + blockSize);
    const hex = plainHexSplit[i - 1] || '';
    return `${String(i + 1).padStart(2)}. ${ciphertextBlockHex} ${hex} ${plain}`;
  };
  const cipherplain = wrapAndSplit(colorized, blockSize * 2)
    .map(mapFunc)
    .join('\n');
  const { barComplete, barIncomplete } = getBar(percent, blockSize * 4 + 5);
  log(
    cipherplain,
    '\n' + barComplete + barIncomplete,
    (percent * 100).toFixed(1).padStart(5) + '%',
    `${blockI + 1}x${byteI + 1}`.padStart(5),
    `${byte}/256`.padStart(7),
    chalk`\n\n{yellow ${String(networkStats.count).padStart(4)}} total network requests`,
    chalk`| last request took {yellow ${String(networkStats.lastDownloadTime).padStart(4)}ms}`,
    chalk`| {yellow ${prettyBytes(networkStats.bytesDown).padStart(7)}} downloaded`,
    chalk`| {yellow ${prettyBytes(networkStats.bytesUp).padStart(7)}} uploaded`,
    isCacheEnabled ? '' : chalk`| cache: {gray disabled}`
  );
}
export function logWarning(txt: string) {
  logUpdate.done();
  console.error(chalk`
{yellow.underline Warning}: ${txt}
`);
}

const stringifyHeaders = (headers: HeadersObject) =>
  Object.entries(headers)
    .map(([k, v]) => `${chalk.gray(k.padEnd(20))}: ${v}`)
    .join('\n');

function logRequest(request: OracleResult) {
  console.log(request.statusCode, request.url);
  console.log(stringifyHeaders(request.headers));
  console.log();
  const size = request.body.length;
  if (size > 1024) {
    console.log(request.body.slice(0, 1024), chalk.gray(`[...and ${(size - 1024).toLocaleString()} more bytes]`));
  } else {
    console.log(request.body);
  }
}

const logHeader = (h: string) => console.log(chalk.blue(`---${h}---`));

interface LogStart {
  blockCount: number;
  totalSize: number;
  initialRequest?: Promise<OracleResult>;
  decryptionSuccess?: Promise<boolean>;
}
export const decryption = {
  async logStart({ blockCount, totalSize, initialRequest: initialRequestPromise, decryptionSuccess }: LogStart) {
    console.log(chalk.bold.white('~~~DECRYPTING~~~'));
    console.log('total bytes:', chalk.yellow(String(totalSize)), '|', 'blocks:', chalk.yellow(String(blockCount - 1)));
    console.log();
    logHeader('making request with original ciphertext');
    const initialRequest = await initialRequestPromise;
    if (initialRequest) {
      if (!(await decryptionSuccess)) {
        logWarning(`Decryption failed for initial request with original ciphertext.
The parameter you provided for determining decryption success seems to be incorrect.`);
      }
      logRequest(initialRequest);
    }
    console.log();
  },
  logCompletion({ foundBytes, interBytes }: { foundBytes: Buffer; interBytes: Buffer }) {
    logUpdate.done();
    console.log();
    logHeader('plaintext printable bytes in utf8');
    console.log(getPrintable(foundBytes.toString('utf8')));
    console.log();
    logHeader('plaintext bytes in hex');
    console.log(foundBytes.toString('hex'));
    console.log();
    logHeader('intermediate bytes in hex');
    console.log(interBytes.toString('hex'));
    console.log();
  },
};
export const encryption = {
  logStart({ blockCount, totalSize }: LogStart) {
    console.log(chalk.bold.white('~~~ENCRYPTING~~~'));
    console.log('total bytes:', chalk.yellow(String(totalSize)), '|', 'blocks:', chalk.yellow(String(blockCount - 1)));
    console.log();
  },
  logCompletion({ foundBytes, interBytes, finalRequest }: { foundBytes: Buffer; interBytes: Buffer; finalRequest?: OracleResult }) {
    logUpdate.done();
    console.log();
    logHeader('ciphertext bytes in hex');
    console.log(foundBytes.toString('hex'));
    console.log();
    logHeader('intermediate bytes in hex');
    console.log(interBytes.toString('hex'));
    console.log();
    if (!finalRequest) return;
    logHeader('final http request');
    logRequest(finalRequest);
    console.log();
  },
};
interface AnalysisLogCompletion {
  responsesTable: string[][];
  statusCodeFreq: { [key: string]: number };
  bodyLengthFreq: { [key: string]: number };
  tmpDirPath?: string;
  networkStats: NetworkStats;
  isCacheEnabled: boolean;
}
export const analysis = {
  logStart({ url, blockSize, tmpDirPath }: { url: string; blockSize: number; tmpDirPath?: string }) {
    console.log(chalk.bold.white('~~~RESPONSE ANALYSIS~~~'));
    console.log('url:', chalk.yellow(url), '|', 'block size:', chalk.yellow(String(blockSize)));
    console.log('will make 256 network requests and analyze responses');
    if (tmpDirPath) console.log('responses will be saved to', chalk.underline(tmpDirPath));
    console.log();
  },
  logCompletion({ responsesTable, statusCodeFreq, bodyLengthFreq, tmpDirPath, networkStats, isCacheEnabled }: AnalysisLogCompletion) {
    const tableConfig: TableUserConfig = {
      border: getBorderCharacters('void'),
      columnDefault: { paddingLeft: 0, paddingRight: 2 },
      singleLine: true,
    };
    const secondTableConfig: TableUserConfig = {
      border: getBorderCharacters('honeywell'),
      columnDefault: { alignment: 'right', paddingLeft: 2, paddingRight: 2 },
      singleLine: true,
    };
    const headerRows = ['Byte', 'Status Code', 'Content Length'].map((x) => chalk.gray(x));
    const scFreqEntries = Object.entries(statusCodeFreq);
    const clFreqEntries = Object.entries(bodyLengthFreq);
    const tabled = table([headerRows, ...responsesTable], tableConfig);
    logHeader('responses');
    console.log(tabled);
    logHeader('status code frequencies');

    console.log(
      table(
        scFreqEntries.map(([k, v]) => [k, v + ' time(s)']),
        secondTableConfig
      )
    );
    logHeader('content length frequencies');
    console.log(
      table(
        clFreqEntries.map(([k, v]) => [k, v + ' time(s)']),
        secondTableConfig
      )
    );
    logHeader('network stats');
    console.log(
      chalk`{yellow ${String(networkStats.count)}} total network requests`,
      chalk`| last request took {yellow ${String(networkStats.lastDownloadTime)}ms}`,
      chalk`| {yellow ${prettyBytes(networkStats.bytesDown)}} downloaded`,
      chalk`| {yellow ${prettyBytes(networkStats.bytesUp)}} uploaded`,
      isCacheEnabled ? '' : chalk`| cache: {gray disabled}`,
      '\n'
    );
    if (tmpDirPath) {
      logHeader('all responses saved to');
      console.log(tmpDirPath + '\n');
    }
    logHeader('automated analysis');
    const commonTips = [
      tmpDirPath && chalk`{gray *} Inspect the saved responses in {underline ${tmpDirPath}}`,
      chalk`{gray *} Change the <block_size> argument. Common block sizes are 8, 16, 32.`,
      chalk`{gray *} Make sure the injection point {underline \{POPAYLOAD\}} is correctly set.`,
    ]
      .filter(Boolean)
      .join('\n');
    if (scFreqEntries.length === 1 && clFreqEntries.length === 1) {
      console.log("Responses don't seem to differ by status code or content length.\n" + commonTips);
    } else if (scFreqEntries.length !== 2 && clFreqEntries.length !== 2) {
      console.log('Responses seem to widely differ.\n' + commonTips);
    } else {
      if (scFreqEntries.length === 2) {
        const errorStatusCode = scFreqEntries.find(([, v]) => v === 255);
        const successStatusCode = scFreqEntries.find(([, v]) => v === 1);
        if (successStatusCode && errorStatusCode) {
          const sc = chalk[getStatusCodeColor(+errorStatusCode[0])](errorStatusCode[0]);
          console.log(chalk`Responses are likely to have a ${sc} status code when a decryption error occurs.\nYou can try specifying ${sc} for the {bold <error>} argument.\n`);
        }
      }
      if (clFreqEntries.length === 2) {
        const errorContentLength = clFreqEntries.find(([, v]) => v === 255);
        const successContentLength = clFreqEntries.find(([, v]) => v === 1);
        if (successContentLength && errorContentLength) {
          console.log(
            'Responses are likely to be sized',
            chalk.yellow(errorContentLength[0]),
            'bytes when a decryption error occurs.',
            tmpDirPath ? chalk`\nYou can find out how the response differs by inspecting the saved responses in\n{underline ${tmpDirPath}}\n` : '\n'
          );
        }
      }
    }
    console.log();
  },
};

export function logError(err: Error) {
  logUpdate.done();
  console.error(chalk.red(err.stack || err.message));
}
