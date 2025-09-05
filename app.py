from flask import Flask, request, jsonify
import base64, os, json, uuid
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# In-memory session store (demo only; replace with Redis/DB in prod)
sessions = {}

KEM_ALG = "Kyber512"
HKDF_SALT = b"TrustGraphDemoSalt"  # demo-only; rotate in prod


def hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=HKDF_SALT,
        info=info,
    )
    return hkdf.derive(key_material)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/session/start")
def session_start():
    # Create a new Kyber KEM context for this session
    server_kem = oqs.KeyEncapsulation(KEM_ALG)
    public_key = server_kem.generate_keypair()

    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "server_kem": server_kem,  # keep until decapsulation completes
        "aes_key": None,
        "trust": 0.99,  # demo trust value
    }

    return jsonify({
        "session_id": session_id,
        "kyber_alg": KEM_ALG,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
    })


@app.post("/session/handshake")
def session_handshake():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    ct_b64 = data.get("ciphertext_b64")
    if not session_id or not ct_b64:
        return jsonify({"error": "missing session_id or ciphertext_b64"}), 400

    sess = sessions.get(session_id)
    if not sess or not sess.get("server_kem"):
        return jsonify({"error": "invalid session or handshake already done"}), 400

    server_kem: oqs.KeyEncapsulation = sess["server_kem"]
    ciphertext = base64.b64decode(ct_b64)

    # Decapsulate to obtain the shared secret
    shared_secret_server = server_kem.decap_secret(ciphertext)

    # Derive AES key using HKDF (bind to session_id for context)
    aes_key = hkdf_derive(shared_secret_server, info=session_id.encode("utf-8"), length=32)

    # Store derived key and dispose kem context
    sess["aes_key"] = aes_key
    # Close and remove kem to avoid reuse
    try:
        server_kem.close()
    except Exception:
        pass
    sess["server_kem"] = None

    return jsonify({"status": "ok", "aes_key_len": len(aes_key)})


@app.post("/session/update")
def session_update():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    nonce_b64 = data.get("nonce_b64")
    ct_b64 = data.get("ciphertext_b64")

    if not session_id or not nonce_b64 or not ct_b64:
        return jsonify({"error": "missing fields"}), 400

    sess = sessions.get(session_id)
    if not sess or not sess.get("aes_key"):
        return jsonify({"error": "unknown session or no AES key"}), 400

    aes_key = sess["aes_key"]
    aesgcm = AESGCM(aes_key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ct_b64)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        return jsonify({"error": f"decrypt failed: {e}"}), 400

    # --- Demo: pretend to update trust based on payload ---
    # Here you would compute trust based on vectors. We'll nudge it.
    trust = max(0.0, min(1.0, sess.get("trust", 0.99) - 0.001))
    sess["trust"] = trust

    return jsonify({"status": "ingested", "received": payload, "trust": trust})


@app.get("/session/trust")
def session_trust():
    session_id = request.args.get("session_id")
    sess = sessions.get(session_id)
    if not sess:
        return jsonify({"error": "unknown session"}), 404
    return jsonify({"session_id": session_id, "trust": sess.get("trust", 0.0)})


if __name__ == "__main__":
    # For local dev only. In prod, run with gunicorn/uvicorn behind TLS.
    app.run(host="0.0.0.0", port=8080, debug=True)