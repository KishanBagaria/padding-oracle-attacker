import zlib from 'zlib';
import Keyv from 'keyv';
import KeyvFile from 'keyv-file';

import { CACHE_FILE_PATH } from './constants';

// TODO: develop, publish keyv-json-file and use it instead of keyv-file
// $ cat poattack-cache.json.gz.txt|base64 -D|gunzip|jq
const cacheStore = new Keyv({
  store: new KeyvFile({
    filename: CACHE_FILE_PATH,
    encode: (obj) => {
      const json = JSON.stringify(obj);
      return zlib.gzipSync(json).toString('base64');
    },
    decode: (txt: string) => {
      const bin = zlib.gunzipSync(Buffer.from(txt, 'base64'));
      const json = bin.toString();
      return JSON.parse(json);
    },
  }),
});

export default cacheStore;
