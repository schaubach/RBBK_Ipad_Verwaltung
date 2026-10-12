// Ersatz für nginx im Test-Stack: liefert den Produktions-Build aus (mit Rückfall auf
// index.html wie try_files) und reicht /api/* an das Backend durch. Ohne Abhängigkeiten,
// damit der Container nichts nachladen muss.
//
//     node static-server.js <build-verzeichnis> <port> <backend-url>
//
// Same-Origin ist Pflicht: index.html bringt eine CSP mit connect-src 'self' mit, ein
// direkter Aufruf von localhost:8001 würde vom Browser blockiert. public/config.js wählt
// den Same-Origin-Weg aber nur auf Port 80/443 - deshalb hängt dieser Server an config.js
// genau eine Zeile an, die ihn auch hier erzwingt. Sonst bleibt der Build unverändert.

const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.resolve(process.argv[2] || 'build');
const port = Number(process.argv[3] || 3000);
const backend = new URL(process.argv[4] || 'http://localhost:8001');

const SAME_ORIGIN = "\n// e2e/static-server.js: wie hinter nginx - API über denselben Ursprung.\n" +
  "window.getBackendURL = function () { return ''; };\n";

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

function weiterreichen(req, res) {
  const anfrage = http.request(
    {
      hostname: backend.hostname,
      port: backend.port,
      path: req.url,
      method: req.method,
      headers: { ...req.headers, host: backend.host },
    },
    (antwort) => {
      res.writeHead(antwort.statusCode, antwort.headers);
      antwort.pipe(res);
    }
  );
  anfrage.on('error', (e) => {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`Backend nicht erreichbar: ${e.message}`);
  });
  req.pipe(anfrage);
}

http
  .createServer((req, res) => {
    const pfad = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (pfad.startsWith('/api/')) return weiterreichen(req, res);

    let datei = path.join(root, pfad);
    if (!datei.startsWith(root + path.sep) && datei !== root) {
      res.writeHead(400).end();
      return;
    }
    if (!fs.existsSync(datei) || fs.statSync(datei).isDirectory()) {
      datei = path.join(root, 'index.html');
    }
    const kopf = {
      'Content-Type': TYPEN[path.extname(datei)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    };
    if (pfad === '/config.js') {
      res.writeHead(200, kopf);
      res.end(fs.readFileSync(datei, 'utf8') + SAME_ORIGIN);
      return;
    }
    res.writeHead(200, kopf);
    fs.createReadStream(datei).pipe(res);
  })
  .listen(port, '0.0.0.0', () => console.log(`static-server: ${root} auf Port ${port}, /api -> ${backend.origin}`));
