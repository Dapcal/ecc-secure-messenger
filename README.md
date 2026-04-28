# 🛡️ Novashield - SMS Secure

Projet portant sur l'implémentation d'une messagerie sécurisée "End-to-End" (E2EE).

## 🚀 Fonctionnalités
- **Échange de clés :** Utilisation du protocole Diffie-Hellman sur courbe elliptique (X25519).
- **Chiffrement symétrique :** AES-GCM (256-bit) pour garantir la confidentialité et l'intégrité.
- **Stockage sécurisé :** Clé privée chiffrée localement via PBKDF2 avant d'être sauvegardée dans le `localStorage`.
- **Identité visuelle :** Génération de QR Codes pour le partage de clés publiques.

## 🛠️ Installation
1. Clonez le dépôt : `git clone https://github.com/Dapcal/ecc-secure-messenger.git`
2. Installez les dépendances : `npm install`
3. Lancez le serveur : `node server.js`

## 👥 Auteur
- BICABA Dapoba Calixte Igor
