const test = require('ava')
const getPort = require('get-port')

const { encrypt } = require('../dist')
const runVulnServer = require('./helpers/vulnerable-server')

const isDecryptionSuccess = ({ statusCode }) => statusCode !== 400

test('encrypts', async (t) => {
  const { server, port } = await runVulnServer({ port: await getPort() })
  const encryption = await encrypt({
    url: `http://localhost:${port}/decrypt?ciphertext=`,
    blockSize: 16,
    logMode: 'none',
    isCacheEnabled: false,
    plaintext: Buffer.from('unicorns rainbows 🦄🌈☀️ foo bar', 'utf8'),
    makeFinalRequest: false,
    isDecryptionSuccess
  })
  t.snapshot(encryption)
  server.close()
})
