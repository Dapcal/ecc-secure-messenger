const http = require('node:http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./novashield.db');

// On ne garde que la table des utilisateurs (Annuaire de clés publiques)
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, public_key TEXT)");
});

const server = http.createServer((req, res) => {
    const url = req.url;

    // --- FICHIERS STATIQUES ---
    let filePath = "";
    let contentType = "text/html";
    if (url === '/' || url === '/index.html') filePath = path.join(__dirname, 'index.html');
    else if (url === '/scripts/main.js') { filePath = path.join(__dirname, 'scripts', 'main.js'); contentType = "application/javascript"; }
    else if (url === '/css/main.css') { filePath = path.join(__dirname, 'css', 'main.css'); contentType = "text/css"; }

    if (filePath) {
        fs.readFile(filePath, (err, content) => {
            if (err) { res.writeHead(404); res.end(); }
            else { res.writeHead(200, { "Content-Type": contentType }); res.end(content); }
        });
        return;
    }

    // --- API ---
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
        try {
            if (url === '/api/register' && req.method === 'POST') {
                const { username, password, publicKey } = JSON.parse(body);
                db.run("INSERT OR REPLACE INTO users VALUES (?, ?, ?)", [username, password, publicKey], () => {
                    res.writeHead(201); res.end(JSON.stringify({ status: "ok" }));
                });
            } 
            else if (url === '/api/login' && req.method === 'POST') {
                const { username, password } = JSON.parse(body);
                db.get("SELECT public_key FROM users WHERE username = ? AND password_hash = ?", [username, password], (err, row) => {
                    if (row) { res.writeHead(200); res.end(JSON.stringify({ publicKey: row.public_key })); }
                    else { res.writeHead(401); res.end(); }
                });
            }
        } catch (e) { res.writeHead(400); res.end(); }
    });

    // Route pour vérifier l'existence et récupérer la clé publique
    if (url.startsWith('/api/key/')) {
        const user = url.split('/').pop();
        db.get("SELECT public_key FROM users WHERE username = ?", [user], (err, row) => {
            if (row) {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ publicKey: row.public_key }));
            } else {
                res.writeHead(404); // Utilisateur non trouvé
                res.end(JSON.stringify({ error: "L'utilisateur n'existe pas dans notre base de données." }));
            }
        });
    }
});

server.listen(3000, () => console.log("Novashield (Mode Outil Crypto) sur le port 3000"));