// Liefert den Produktions-Build aus - mit Rückfall auf index.html wie im nginx
// (try_files $uri /index.html). Ohne Abhängigkeiten, damit der Container nichts nachladen muss.
//
//     node static-server.js <build-verzeichnis> <port>

const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.resolve(process.argv[2] || 'build');
const port = Number(process.argv[3] || 3000);

const TYPEN = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.map': 'application/json; charset=utf-8',
};

http
  .createServer((req, res) => {
    const pfad = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    let datei = path.join(root, pfad);
    if (!datei.startsWith(root + path.sep) && datei !== root) {
      res.writeHead(400).end();
      return;
    }
    if (!fs.existsSync(datei) || fs.statSync(datei).isDirectory()) {
      datei = path.join(root, 'index.html');
    }
    res.writeHead(200, {
      'Content-Type': TYPEN[path.extname(datei)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    fs.createReadStream(datei).pipe(res);
  })
  .listen(port, '0.0.0.0', () => console.log(`static-server: ${root} auf Port ${port}`));
