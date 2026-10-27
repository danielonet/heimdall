// Copies the product screenshots from docs/images/ so the repo keeps one copy only,
// and publishes install/get-heimdall.sh as /install.sh.
import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dest = resolve(here, '../public/images');
mkdirSync(dest, { recursive: true });
cpSync(resolve(here, '../../docs/images'), dest, { recursive: true });
console.log('copy-assets: docs/images -> public/images');

// The install script is published from the repo, so the page's command and the script on GitHub cannot differ.
const script = readFileSync(resolve(here, '../../install/get-heimdall.sh'));
writeFileSync(resolve(here, '../public/install.sh'), script);
writeFileSync(resolve(here, '../public/install.sh.sha256'), `${createHash('sha256').update(script).digest('hex')}  install.sh\n`);
console.log('copy-assets: install/get-heimdall.sh -> public/install.sh (+ .sha256)');
