let myKeyPair = null;
let sessionUser = null;
let sessionPassword = null;
let currentAuthMode = 'login';
let html5QrCode = null;

const pack = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unpack = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

// --- CRYPTO LOGIC ---
async function deriveStorageKey(password, salt) {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

// --- CHIFFREMENT ---
async function encryptOnly() {
    const dest = document.getElementById('dest-username').value;
    const msg = document.getElementById('plain-msg').value;
    if (!dest || !msg) return alert("Champs manquants.");

    try {
        const res = await fetch(`/api/key/${dest}`);
        if (!res.ok) throw new Error("Utilisateur introuvable dans la base de données.");
        const data = await res.json();
        
        const destKey = await window.crypto.subtle.importKey("jwk", JSON.parse(atob(data.publicKey)), { name: "X25519" }, true, []);
        const sharedKey = await window.crypto.subtle.deriveKey(
            { name: "X25519", public: destKey }, myKeyPair.privateKey,
            { name: "AES-GCM", length: 256 }, false, ["encrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const enc = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, sharedKey, new TextEncoder().encode(msg));
        const out = new Uint8Array(iv.length + enc.byteLength);
        out.set(iv); out.set(new Uint8Array(enc), iv.length);
        
        document.getElementById('cipher-output').value = pack(out);
    } catch (e) { alert(e.message); }
}

// --- DÉCHIFFREMENT ---
async function decryptMessage() {
    const sender = document.getElementById('sender-username').value;
    const cipher = document.getElementById('cipher-input').value;
    if (!sender || !cipher) return alert("Champs manquants.");

    try {
        const res = await fetch(`/api/key/${sender}`);
        if (!res.ok) throw new Error("Expéditeur inconnu dans la BD.");
        const data = await res.json();
        
        const senderKey = await window.crypto.subtle.importKey("jwk", JSON.parse(atob(data.publicKey)), { name: "X25519" }, true, []);
        const sharedKey = await window.crypto.subtle.deriveKey(
            { name: "X25519", public: senderKey }, myKeyPair.privateKey,
            { name: "AES-GCM", length: 256 }, false, ["decrypt"]
        );

        const raw = unpack(cipher);
        const dec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.slice(0, 12) }, sharedKey, raw.slice(12));
        document.getElementById('decrypted-msg').innerText = new TextDecoder().decode(dec);
    } catch (e) { alert("Erreur : Cryptogramme ou expéditeur invalide."); }
}

// --- GESTION DE L'IDENTITÉ ET RÉVOCATION ---
async function revokeKeys() {
    const confirmPass = prompt("Veuillez saisir votre mot de passe de connexion pour générer de nouvelles clés :");
    if (confirmPass !== sessionPassword) return alert("Mot de passe incorrect.");

    if (!confirm("Voulez-vous vraiment écraser votre identité actuelle ? Vos anciens messages deviendront indéchiffrables.")) return;

    try {
        // 1. Génération de nouvelles clés
        const keys = await window.crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"]);
        const pubJwk = await window.crypto.subtle.exportKey("jwk", keys.publicKey);
        const pubB64 = btoa(JSON.stringify(pubJwk));

        // 2. Mise à jour sur le serveur (Annuaire)
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: sessionUser, password: sessionPassword, publicKey: pubB64 })
        });

        if (res.ok) {
            // 3. Sauvegarde locale chiffrée
            await saveIdentityLocally(sessionUser, sessionPassword, keys);
            myKeyPair = keys;
            
            // 4. Mise à jour de l'UI
            document.getElementById('my-public-key-display').value = pubB64;
            generateQRCode(sessionUser, pubB64);
            alert("Identité mise à jour avec succès.");
        } else {
            throw new Error("Erreur serveur lors de la mise à jour.");
        }
    } catch (e) {
        alert("Erreur lors de la révocation : " + e.message);
    }
}

// --- GESTION QR CODE ---
function generateQRCode(user, pub) {
    const qrContainer = document.getElementById('qrcode-container');
    qrContainer.innerHTML = "";
    new QRCode(qrContainer, {
        text: JSON.stringify({ u: user, k: pub }),
        width: 160, height: 160,
        colorDark : "#0f172a", colorLight : "#ffffff"
    });
}

function showDashboard(user, pub) {
    document.getElementById('auth-view').style.display = 'none';
    document.getElementById('main-view').style.display = 'block';
    document.getElementById('auth-status').style.display = 'flex';
    document.getElementById('active-user-name').innerText = user;
    
    document.getElementById('my-public-key-display').value = pub;
    generateQRCode(user, pub);
}

function startScanner() {
    document.getElementById('qr-reader').style.display = 'block';
    html5QrCode = new Html5Qrcode("qr-reader");
    html5QrCode.start({ facingMode: "environment" }, { fps: 10, qrbox: 250 }, 
        (text) => {
            try {
                const data = JSON.parse(text);
                if(data.u) {
                    document.getElementById('sender-username').value = data.u;
                    stopScanner();
                    alert("Utilisateur " + data.u + " détecté.");
                }
            } catch(e) {}
        }
    );
}

function stopScanner() {
    if(html5QrCode) {
        html5QrCode.stop().then(() => {
            document.getElementById('qr-reader').style.display = 'none';
        });
    }
}

// --- AUTH & AMNÉSIE ---
async function handleAuth() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    
    if (currentAuthMode === 'register') {
        const keys = await window.crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"]);
        const pubJwk = await window.crypto.subtle.exportKey("jwk", keys.publicKey);
        const pubB64 = btoa(JSON.stringify(pubJwk));
        const res = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass, publicKey: pubB64 })
        });
        if (res.ok) {
            await saveIdentityLocally(user, pass, keys);
            alert("Compte créé !");
            setAuthMode('login');
        }
    } else {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        if (res.ok) {
            const data = await res.json();
            const keys = await loadIdentityLocally(user, pass);
            if(!keys) return alert("Clé privée introuvable sur cet appareil.");
            myKeyPair = keys; sessionUser = user; sessionPassword = pass;
            showDashboard(user, data.publicKey);
        } else alert("Identifiants incorrects.");
    }
}

function logout() {
    stopScanner();
    myKeyPair = null; sessionUser = null; sessionPassword = null;
    document.querySelectorAll('input, textarea').forEach(el => el.value = "");
    document.getElementById('qrcode-container').innerHTML = "";
    document.getElementById('decrypted-msg').innerText = "---";
    location.reload();
}

// --- PERSISTANCE ---
async function saveIdentityLocally(u, p, k) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const sKey = await deriveStorageKey(p, salt);
    const privJwk = await window.crypto.subtle.exportKey("jwk", k.privateKey);
    const enc = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, sKey, new TextEncoder().encode(JSON.stringify(privJwk)));
    localStorage.setItem(`nova_id_${u}`, JSON.stringify({ salt: pack(salt), iv: pack(iv), priv: pack(enc), pub: await window.crypto.subtle.exportKey("jwk", k.publicKey) }));
}

async function loadIdentityLocally(u, p) {
    const data = JSON.parse(localStorage.getItem(`nova_id_${u}`));
    if(!data) return null;
    try {
        const sKey = await deriveStorageKey(p, unpack(data.salt));
        const dec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: unpack(data.iv) }, sKey, unpack(data.priv));
        return {
            privateKey: await window.crypto.subtle.importKey("jwk", JSON.parse(new TextDecoder().decode(dec)), { name: "X25519" }, true, ["deriveKey", "deriveBits"]),
            publicKey: await window.crypto.subtle.importKey("jwk", data.pub, { name: "X25519" }, true, [])
        };
    } catch(e) { return null; }
}

// --- TABS & UI ---
function switchTab(e, id) {
    document.querySelectorAll('.tab-pane').forEach(p => p.style.display = 'none');
    document.querySelectorAll('.tab-link').forEach(l => l.classList.remove('active'));
    document.getElementById(id).style.display = 'block';
    if(e) e.currentTarget.classList.add('active');
    stopScanner();
}

function setAuthMode(m) {
    currentAuthMode = m;
    document.getElementById('tab-login-btn').classList.toggle('active', m === 'login');
    document.getElementById('tab-register-btn').classList.toggle('active', m === 'register');
}

function copyToClipboard(id) {
    const el = document.getElementById(id);
    el.select();
    navigator.clipboard.writeText(el.value);
    alert("Copié !");
}