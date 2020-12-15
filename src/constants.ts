const pkg = require('../package.json'); // eslint-disable-line

const GITHUB_REPO_URL = `https://github.com/${pkg.repository}`;

export const DEFAULT_USER_AGENT = `${pkg.name}/${pkg.version} (${GITHUB_REPO_URL})`;
export const CACHE_FILE_PATH = 'poattack-cache.json.gz.txt';

export const PKG_NAME = pkg.name;
export const PKG_VERSION = pkg.version;
