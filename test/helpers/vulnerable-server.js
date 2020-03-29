const crypto = require('crypto')
const util = require('util')
const express = require('express')
const bodyParser = require('body-parser')
const { encrypt, decrypt } = require('./crypto')

const randomBytes = util.promisify(crypto.randomBytes)

const DEFAULT_KEY = Buffer.from('00112233445566778899112233445566', 'hex')
const DEFAULT_ENCODING = 'hex'

function run(args) {
  const { port = 2020, loggingEnabled, encryptionAlgo = 'aes-128-cbc', key = DEFAULT_KEY } = args || {}
  const blockSize = +args.blockSize || 16

  const app = express()
  app.disable('x-powered-by')
  app.disable('etag')
  app.use(bodyParser.urlencoded({ extended: false }))
  app.use(bodyParser.json())

  app.get('/encrypt', async (req, res) => {
    const { plaintext } = req.query
    if (!plaintext) {
      res.sendStatus(400)
      return
    }
    const iv = await randomBytes(blockSize)
    const plaintextBuffer = Buffer.from(plaintext, 'utf8')
    const ciphertext = encrypt(encryptionAlgo, plaintextBuffer, key, iv)
    res.send(Buffer.concat([iv, ciphertext]).toString(DEFAULT_ENCODING))
  })
  app.all('/decrypt', (req, res) => {
    const { ciphertext, includeHeaders = false } = req.query
    if (!ciphertext) {
      res.sendStatus(400)
      return
    }
    const fullBuffer = Buffer.from(ciphertext, DEFAULT_ENCODING)
    const ivBuffer = fullBuffer.slice(0, blockSize)
    const ciphertextBuffer = fullBuffer.slice(blockSize)
    const reqDetails = [req.method, req.headers, req.body]
    try {
      const decrypted = decrypt(encryptionAlgo, ciphertextBuffer, key, ivBuffer)
      const txt = decrypted.toString('utf8')
      if (loggingEnabled) console.log(200, ciphertext, txt, ...reqDetails)
      if (includeHeaders) res.json({ headers: req.headers, decrypted: txt })
      else res.send('OK')
    } catch (err) {
      if (loggingEnabled) console.log(400, ciphertext, err.message, ...reqDetails)
      res.status(400).send(err.message)
    }
  })

  return new Promise((resolve) => {
    const server = app.listen(port, () => resolve({ port, server }))
  })
}

module.exports = run

if (require.main === module) {
  run({ loggingEnabled: true }).then(({ port }) => {
    console.log(`listening on http://localhost:${port}/`)
  }).catch(console.error)
}
