'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Explicit public surface: adding a server file never publishes it as an asset.
// API handlers and their dependencies stay in the source for Vercel's bundler.
const PUBLIC_FILES = Object.freeze([
  '404.html', 'activate.html', 'ajuda.html', 'auth-callback.html', 'cliente.html',
  'download.html', 'index.html', 'planos.html', 'privacidade.html', 'produto.html',
  'recursos.html', 'redefinir-senha.html', 'reembolso.html', 'seguranca.html', 'termos.html',
  'auth-callback.js', 'auth-client.js', 'controls.js', 'password-reset.js', 'script.js', 'site-shell.js',
  'client.css', 'controls.css', 'styles.css',
  'assets/google-logo.svg', 'assets/paxinbot-mark.svg', 'assets/paxin-core.js',
  'assets/paxin-core.css', 'assets/vendor/supabase-2.105.0.js',
  'releases/stable-win32-x64.json'
]);

function buildPublic(root = __dirname) {
  root = fs.realpathSync(root);
  const output = path.join(root, 'public-site');
  const approved = new Set(PUBLIC_FILES);
  const normalized = value => value.replaceAll('\\', '/');
  function checkExisting(directory) {
    if (fs.lstatSync(directory).isSymbolicLink()) throw new Error('Refusing linked build output.');
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Refusing linked build output.');
      if (entry.isDirectory()) checkExisting(file);
      else if (!entry.isFile() || !approved.has(normalized(path.relative(output, file)))) {
        throw new Error('Unexpected file in public-site; inspect before rebuilding.');
      }
    }
  }
  // Validate inputs before removing this build's previous generated output.
  for (const relative of PUBLIC_FILES) {
    const source = path.join(root, relative);
    if (!fs.lstatSync(source).isFile() || fs.lstatSync(source).isSymbolicLink()
        || fs.realpathSync(source).toLowerCase() !== source.toLowerCase()) {
      throw new Error(`Invalid public input: ${relative}`);
    }
  }
  if (fs.existsSync(output)) {
    checkExisting(output);
    if (fs.realpathSync(output).toLowerCase() !== output.toLowerCase()
        || path.relative(root, output) !== 'public-site') throw new Error('Invalid build output path.');
    fs.rmSync(output, { recursive: true, force: false });
  }
  fs.mkdirSync(output);
  for (const relative of PUBLIC_FILES) {
    const destination = path.join(output, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(root, relative), destination, fs.constants.COPYFILE_EXCL);
  }
  return { output, publicFiles: PUBLIC_FILES.length };
}
module.exports = { PUBLIC_FILES, buildPublic };
if (require.main === module) console.log(JSON.stringify(buildPublic()));
