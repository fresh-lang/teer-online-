const fs = require('fs');
const path = require('path');
const root = __dirname;
const out = path.join(root, 'www');
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
for (const name of ['index.html','admin.html','manifest.json','sw.js','logo.png','icon-192.png','icon-512.png']) {
  const src = path.join(root, name);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(out, name));
}
