# Secure E2EE Chatbot over QQ (RSA + AES‑GCM)

A **secure-by-design chatbot** that brings end‑to‑end encryption (E2EE) to QQ messaging by combining **RSA‑OAEP** for public‑key key exchange and **AES‑GCM** for authenticated symmetric encryption. The project includes a desktop GUI for key generation and message encryption/decryption, a bot backend bridged to QQ via **Napcat**, and a simple on‑wire message format for ciphertext transport.

> This README summarizes the full project design, security model, implementation details, quick-start steps, and demo screenshots.

---

## Highlights

- **Hybrid encryption (KEM‑DEM):** RSA‑OAEP encapsulates per‑session AES keys; AES‑GCM provides fast, authenticated encryption for every message.
- **True E2EE workflow:** Keys are generated and used locally; messages remain encrypted across the third‑party platform.
- **GUI‑driven UX:** One‑click session setup, encryption/decryption, and image/file encryption.
- **QQ integration:** The bot is connected through **Napcat** to send/receive Base64‑encoded secure payloads.
- **Key rotation ready:** Supports re‑keying per N messages or time interval.

---

## Architecture

The system is implemented as **four cooperating modules**:

1. **Frontend GUI (tkinter):** keypair generation, AES key management, encrypt/decrypt text and images, logs.
2. **Crypto engine (Python, `cryptography`):** RSA‑OAEP, AES‑GCM, padding/serialization, Base64 utilities.
3. **Chatbot backend (Napcat bridge):** detects secure payloads, decrypts, invokes response logic/LLMs, re‑encrypts and replies.
4. **Transport & envelope:** Base64‑encoded JSON envelopes travel through QQ messages.

**Communication phases**

- **Phase I – Session setup**: User sends RSA public key → bot replies with RSA‑encrypted AES key (Base64) → user decrypts and stores AES session key.
- **Phase II – Secure chat**: Both sides use AES‑GCM (fresh nonce per message) to exchange ciphertexts with integrity tags.

---

## Screenshots

### 1) RSA public key ↔ AES session key (handshake)
![Handshake](assets/screenshot-handshake.png)

### 2) AES‑GCM encryption/decryption in the GUI
![GUI](assets/screenshot-gui.png)

> Keep these images inside `assets/` beside this README so the links render on GitHub.

---

## How It Works (Step‑by‑Step)

1. **Generate RSA keypair (user)**  
   The GUI creates a 2048‑bit RSA keypair and displays the PEM‑encoded public/private keys.

2. **Share public key (user → bot)**  
   Paste the **public key PEM** into the QQ chat to start secure mode.

3. **Encapsulate AES key (bot)**  
   Bot generates a random 256‑bit AES key and encrypts it with **RSA‑OAEP(SHA‑256)**. The Base64(CK) is sent back.

4. **Recover AES key (user)**  
   GUI uses the local RSA private key to decrypt CK and store the session **AES key**.

5. **Secure messaging (both sides)**  
   For every message: generate a fresh 96‑bit **IV/nonce**, run **AES‑GCM**, and send Base64‑encoded `(iv, tag, ciphertext)` in a JSON envelope.

6. **Verify & decrypt**  
   Receiver checks the GCM tag before decryption. If verification fails, the payload is rejected.

---

## Message Envelope (wire format)

```json
{
  "type": "secure_msg",
  "mode": "GCM",
  "iv": "<Base64>",
  "ciphertext": "<Base64>",
  "tag": "<Base64>",
  "aes_key": "<RSA‑OAEP encapsulated key (optional during rekey)>"
}
```

---

## Security Design

- **Asymmetric:** RSA‑OAEP (SHA‑256) for key encapsulation, 2048‑bit modulus.
- **Symmetric:** AES‑256‑GCM for confidentiality + integrity (128‑bit tag), per‑message random nonce (96‑bit).
- **Best practices:** Never reuse nonces; rotate AES keys periodically; authenticate before decryption.
- **Threat model covered:** passive eavesdropping, tampering, replay, and chosen‑plaintext attempts on the symmetric layer.

> **Note:** In group chats or multi‑user contexts, add sender binding (e.g., per‑sender key cache + optional digital signatures/HMAC).

---

## Quick Start

### Prerequisites
- Python **3.10+**
- `pip install cryptography gmpy2 pyasn1`  (plus your QQ/Napcat runtime)
- Windows/macOS/Linux supported for the GUI

### Run
```bash
# 1) Clone your repo and install deps
pip install -r requirements.txt   # or install the few libraries above

# 2) Start the GUI tool
python gui.py

# 3) In QQ:
#   a. Click “Start Secure Session” in the GUI to generate and send your RSA public key
#   b. Paste the bot's RSA‑encrypted AES key into the GUI to finish the handshake
#   c. Use the AES tab to encrypt your messages; paste ciphertext into QQ
```

---

## Tech Stack

- **Language:** Python 3.10+  
- **Crypto libs:** `cryptography` (RSA‑OAEP, AES‑GCM), `gmpy2` (safe primes), `pyasn1` (PEM/DER)  
- **GUI:** tkinter  
- **Bridge:** Napcat (QQ bot middleware)

---

## Suggested Repository Layout

```
secure-e2ee-chatbot/
├─ README.md
├─ requirements.txt
├─ gui.py                 # Tkinter app: RSA/AES tabs, secure chat helper
├─ crypto/
│  ├─ rsa_tool.py         # Keygen, serialize/deserialize
│  └─ aes_gcm.py          # AES‑GCM helpers (encrypt/decrypt, Base64)
├─ bot/
│  └─ main.py             # Napcat event loop, decrypt/route/reply/re‑encrypt
├─ assets/
│  ├─ screenshot-handshake.png
│  └─ screenshot-gui.png
└─ docs/
   └─ FinalReport.pdf     # (optional) detailed report
```

---

## Roadmap

- Auto‑detect & auto‑decrypt incoming AES keys (no manual paste).
- Per‑user **session key cache** and automatic **key rotation**.
- Optional digital signatures (RSA‑SHA256) or HMAC for **origin authentication**.
- Local LLM integration for fully private, encrypted semantic chat.

---

## License

Choose one (e.g., **MIT**). If you need a ready‑made `LICENSE`, create it with your preferred terms.

---

## Acknowledgements

- Napcat community for the QQ bridge.
- Open‑source Python crypto ecosystem.

---

> If you move this README into your GitHub repo, keep the two images in `assets/` so they render properly.
