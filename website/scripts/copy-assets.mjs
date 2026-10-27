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

// The logo is the dashboard's own, so the site and the product cannot show different marks.
// It goes under src/ so Astro can resize it (header, favicon, hero).
mkdirSync(resolve(here, '../src/assets'), { recursive: true });
cpSync(resolve(here, '../../frontend/src/assets/heimdall-icon.png'), resolve(here, '../src/assets/heimdall.png'));
cpSync(resolve(here, '../../frontend/src/assets/heimdall-icon.png'), resolve(dest, 'heimdall.png')); // the manual's favicon
console.log('copy-assets: frontend/src/assets/heimdall-icon.png -> src/assets/heimdall.png, public/images/heimdall.png');

// The install script is published from the repo, so the page's command and the script on GitHub cannot differ.
const script = readFileSync(resolve(here, '../../install/get-heimdall.sh'));
writeFileSync(resolve(here, '../public/install.sh'), script);
writeFileSync(resolve(here, '../public/install.sh.sha256'), `${createHash('sha256').update(script).digest('hex')}  install.sh\n`);
console.log('copy-assets: install/get-heimdall.sh -> public/install.sh (+ .sha256)');
