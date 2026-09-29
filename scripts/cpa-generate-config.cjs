'use strict';
// Offline provisioning helper. Writes new files exclusively; prints no secrets.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function generate(directory, releaseId) {
  const root = path.resolve(directory);
  const repository = path.resolve(__dirname, '..');
  const relative = path.relative(repository, root);
  if (!relative.startsWith('..') && !path.isAbsolute(relative)) throw new Error('Use a private directory outside the site repository.');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(releaseId)) throw new Error('Invalid release ID.');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const secretFile = path.join(root, 'cpa-server-secrets.json');
  const publicFile = path.join(root, 'cpa-public-config.json');
  if (fs.existsSync(secretFile) || fs.existsSync(publicFile)) throw new Error('Refusing to replace existing keys.');
  const kid = `cpa-${Date.now()}`;
  const pair = crypto.generateKeyPairSync('ed25519');
  const privateKey = pair.privateKey.export({ type:'pkcs8', format:'der' }).toString('base64url');
  const publicKey = pair.publicKey.export({ type:'spki', format:'der' }).toString('base64url');
  const secrets = {
    CPA_LICENSE_HMAC_PEPPERS: JSON.stringify({ v1:crypto.randomBytes(32).toString('base64url') }),
    CPA_LICENSE_HMAC_CURRENT_VERSION: 'v1',
    CPA_LICENSE_SIGNING_KEYS: JSON.stringify({ [kid]:privateKey }),
    CPA_LICENSE_SIGNING_CURRENT_KID: kid
  };
  fs.writeFileSync(secretFile, JSON.stringify(secrets, null, 2), { flag:'wx', mode:0o600 });
  fs.writeFileSync(publicFile, JSON.stringify({ api_url:'https://www.paxincpa.store/api/licenses', release_id:releaseId,
    public_keys:{ [kid]:publicKey }, build_mode:'production' }, null, 2), { flag:'wx', mode:0o600 });
  return { publicFile, secretFile };
}
module.exports = { generate };
if (require.main === module) {
  if (process.argv.length !== 4) throw new Error('Usage: node cpa-generate-config.cjs PRIVATE-DIRECTORY RELEASE-ID');
  generate(process.argv[2], process.argv[3]);
  console.log('Configuration written. Import server secrets securely; only public config goes to the build.');
}
