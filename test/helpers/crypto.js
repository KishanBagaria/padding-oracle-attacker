const crypto = require('crypto')

function encrypt(encryptionAlgo, plaintext, key, iv) {
  const cipher = crypto.createCipheriv(encryptionAlgo, key, iv)
  return Buffer.concat([cipher.update(plaintext), cipher.final()])
}
function decrypt(encryptionAlgo, ciphertext, key, iv) {
  const decipher = crypto.createDecipheriv(encryptionAlgo, key, iv)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

module.exports = { encrypt, decrypt }
