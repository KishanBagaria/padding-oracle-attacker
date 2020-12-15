const test = require('ava');
const getPort = require('get-port');

const { decrypt } = require('../dist');
const runVulnServer = require('./helpers/vulnerable-server');

const isDecryptionSuccess = ({ statusCode }) => statusCode !== 400;

test('decrypts', async (t) => {
  const { server, port } = await runVulnServer({ port: await getPort() });
  const decryption = await decrypt({
    url: `http://localhost:${port}/decrypt?ciphertext=`,
    blockSize: 16,
    logMode: 'none',
    isCacheEnabled: false,
    ciphertext: Buffer.from('e3e70d8599206647dbc96952aaa209d75b4e3c494842aa1aa8931f51505df2a8a184e99501914312e2c50320835404e9', 'hex'),
    startFromFirstBlock: true,
    isDecryptionSuccess,
  });
  t.snapshot(decryption);
  server.close();
});
