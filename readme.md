# padding-oracle-attacker

CLI tool and library to execute [padding oracle attacks](https://en.wikipedia.org/wiki/Padding_oracle_attack) easily, with support for concurrent network requests and an elegant UI.

![poattack decrypt demo](media/poattack-decrypt.gif)

[![Build Status](https://travis-ci.org/KishanBagaria/padding-oracle-attacker.svg)](https://travis-ci.org/KishanBagaria/padding-oracle-attacker)

## Install

```sh
$ yarn global add padding-oracle-attacker
```
or
```sh
$ npm install --global padding-oracle-attacker
```

## CLI Usage

```
Usage
  $ padding-oracle-attacker decrypt <url> hex:<ciphertext_hex> <block_size> <error> [options]

  $ padding-oracle-attacker encrypt <url> <plaintext>          <block_size> <error> [options]
  $ padding-oracle-attacker encrypt <url> hex:<plaintext_hex>  <block_size> <error> [options]

Commands
  decrypt                 Finds the plaintext (foobar) for given ciphertext (hex:0123abcd)
  encrypt                 Finds the ciphertext (hex:abcd1234) for given plaintext (foo=bar)

Arguments
  <url>                   URL to attack. Payload will be inserted at the end by default. To specify
                          a custom injection point, include {POPAYLOAD} in a header (-H),
                          request body (-d) or the URL
  <block_size>            Block size used by the encryption algorithm on the server
  <error>                 The string present in response when decryption fails on the server.
                          Specify a string present in the HTTP response body (like PaddingException)
                          or status code of the HTTP response (like 400)

Options
  -c, --concurrency       Requests to be sent concurrently                      [default: 64]
      --disable-cache     Disable network cache. Saved to                       [default: false]
                          poattack-cache.json.gz.txt by default
  -X, --method            HTTP method to use while making request               [default: GET]
  -H, --header            Headers to be sent with request.
                            -H 'Cookie: cookie1' -H 'User-Agent: Googlebot/2.1'
  -d, --data              Request body
                            JSON string: {"id": 101, "foo": "bar"}
                            URL encoded: id=101&foo=bar
                          Make sure to specify the Content-Type header.

  -e, --payload-encoding  Ciphertext payload encoding.                          [default: hex]
                            base64          FooBar+/=
                            base64-urlsafe  FooBar-_
                            hex             deadbeef
                            hex-uppercase   DEADBEEF
                            base64(xyz)     Custom base64 ('xyz' represent characters for '+/=')

  --start-from-1st-block  Start processing from the first block instead         [default: false]
                          of the last (only works with decrypt mode)

Examples
  $ poattack decrypt http://localhost:2020/decrypt?ciphertext=
      e3e70d8599206647dbc96952aaa209d75b4e3c494842aa1aa8931f51505df2a8a184e99501914312e2c50320835404e9
      16 400
  $ poattack encrypt http://localhost:2020/decrypt?ciphertext= "foo bar 🦄" 16 400

Aliases
  poattack
  padding-oracle-attack
```

## Library API

```js
const { decrypt, encrypt } = require('padding-oracle-attacker')
// or
import { decrypt, encrypt } from 'padding-oracle-attacker'

const { blockCount, totalSize, foundBytes, interBytes } = await decrypt(options)

const { blockCount, totalSize, foundBytes, interBytes, finalRequest } = await encrypt(options)
```

#### `decrypt(options: Object): Promise`
#### `encrypt(options: Object): Promise`

##### Required options

###### `url: string`
URL to attack. Payload will be appended at the end by default. To specify a custom injection point, include `{POPAYLOAD}` in the URL, a header (`requestOptions.headers`) or the request body (`requestOptions.data`)

###### `blockSize: number`
Block size used by the encryption algorithm on the server.

###### `isDecryptionSuccess: ({ statusCode, headers, body }) => boolean`
Function that returns true if the server response indicates decryption was successful.

###### `ciphertext: Buffer` (`decrypt` only)
Ciphertext to decrypt.

###### `plaintext: Buffer` (`encrypt` only)
Plaintext to encrypt. Padding will be added automatically. Example: `Buffer.from('foo bar', 'utf8')`

---

##### Optional options

###### `concurrency: number = 128`
Network requests to be sent concurrently.

###### `isCacheEnabled: boolean = true`
Responses are cached by default and saved to `poattack-cache.json.gz.txt`. Set to `false` to disable caching.

###### `requestOptions: { method, headers, data }`
###### `requestOptions.method: string`
HTTP method to use while making the request. `GET` by default. `POST`, `PUT`, `DELETE` are some valid options.

###### `requestOptions.headers: { string: string }`
Headers to be sent with request. Example: `{ 'Content-Type': 'application/x-www-form-urlencoded' }`

###### `requestOptions.body: string`
Request body. Can be a JSON string, URL encoded params etc. `Content-Type` header has to be set manually.

###### `logMode: 'full'|'minimal'|'none' = 'full'`
`full`: Log everything to console (default)  
`minimal`: Log only after start and completion to console  
`none`: Log nothing to console

###### `transformPayload: (ciphertext: Buffer) => string`
Function to convert the `ciphertext` into a string when making a request. By default, `ciphertext` is encoded in hex and inserted at the injection point (URL end unless `{POPAYLOAD}` is present).

---
##### Optional options (`decrypt` only)

###### `alreadyFound: Buffer`
Plaintext bytes already known/found that can be skipped (from the end). If you provide a `Buffer` of ten bytes, the last ten bytes will be skipped.

###### `initFirstPayloadBlockWithOrigBytes: boolean = false`
Initialize first payload block with original `ciphertext` bytes instead of zeroes.  
Example: `abcdef12345678ff 1111111111111111` instead of `00000000000000ff 1111111111111111`

###### `startFromFirstBlock: boolean = false`
Start processing from the first block instead of the last.

###### `makeInitialRequest: boolean = true`
Make an initial request with the original `ciphertext` provided and log server response to console to allow the user to make sure network requests are being sent correctly.

---
##### Optional options (`encrypt` only)

###### `makeFinalRequest: boolean = true`
After finding the `ciphertext` bytes for the new `plaintext`, make a final request with the found bytes and log the server response to console.

###### `lastCiphertextBlock: Buffer`
Custom ciphertext for the last block. Last block is just zeroes by default (`000000000000000`).

## Developing

`padding-oracle-attacker` is written in TypeScript. If you'd like to modify the source files and run them, you can either compile the files into JS first and run them using node, or use [ts-node](https://www.npmjs.com/package/ts-node).  
Example: `yarn build` then `node dist/cli ...` or simply `ts-node src/cli ...`

##### `yarn build` or `npm run build`
Builds the TypeScript files inside the `src` directory to JS files and outputs them to the `dist` directory.

##### `yarn clean` or `npm run clean`
Deletes the `dist` directory.

##### `yarn lint` or `npm run lint`
Lints the files using eslint.

##### `yarn test` or `npm run test`
Lints and runs the tests using ava.

##### `node test/helpers/vulnerable-server.js`
Runs the test server which is vulnerable to padding oracle attacks at <http://localhost:2020>

## Related

* [PadBuster](https://github.com/GDSSecurity/PadBuster) (Perl)
* [Padding Oracle Attack](https://github.com/mpgn/Padding-oracle-attack) (Python)
* [Poracle](https://github.com/iagox86/poracle) (Ruby)

## License

MIT © [Kishan Bagaria](https://kishanbagaria.com)
