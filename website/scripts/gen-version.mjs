// Writes src/data/version.json: the release this build was made from, shown top right on every page.
// Tags must be present (CI checks out with fetch-depth 0); without them the page says "dev".
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const git = (...args) => execFileSync('git', args, { cwd: here, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

let version = 'dev';
let commit = '';
try {
  commit = git('rev-parse', '--short', 'HEAD');
  // "v0.1.6" on a tagged commit; "v0.1.5+abc1234" when commits came after the last tag.
  const described = git('describe', '--tags', '--match', 'v[0-9]*', '--long');
  const m = described.match(/^(v\d+\.\d+\.\d+)-(\d+)-g[0-9a-f]+$/);
  if (m) version = m[2] === '0' ? m[1] : `${m[1]}+${commit}`;
} catch {
  // No git or no tags (a tarball, a shallow clone): the page says "dev" rather than guessing.
}

const dest = resolve(here, '../src/data/version.json');
mkdirSync(dirname(dest), { recursive: true });
writeFileSync(dest, JSON.stringify({ version, commit }, null, 2) + '\n');
console.log(`gen-version: ${version}${commit ? ` (${commit})` : ''}`);
