from flask import Flask, request, jsonify
import base64, os, json, uuid
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# In-memory session store (demo only; replace with Redis/DB in prod)
# This dictionary holds session data keyed by session_id
sessions = {}

# Constants for the post-quantum KEM algorithm and HKDF salt
KEM_ALG = "Kyber512"  # Kyber512 is a NIST post-quantum KEM candidate
HKDF_SALT = b"TrustGraphDemoSalt"  # Salt used in HKDF key derivation; rotate in production


def hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a symmetric key from shared secret material using HKDF-SHA256.
    - key_material: input keying material (shared secret from KEM)
    - info: context-specific info (e.g., session_id) to bind the key derivation
    - length: desired output key length in bytes
    Returns a securely derived key of specified length.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=HKDF_SALT,
        info=info,
    )
    return hkdf.derive(key_material)


@app.get("/health")
def health():
    """
    Simple health check endpoint.
    Returns a JSON indicating the service status.
    """
    return {"status": "ok"}


@app.post("/session/start")
def session_start():
    """
    Start a new session by creating a Kyber512 KEM context and generating a public key.
    This public key is sent to the client to perform the encapsulation step.
    
    Post-quantum cryptography usage:
    - Uses Kyber512 KEM to generate a keypair.
    - The server keeps the private context to later decapsulate the ciphertext from client.
    
    Returns:
    - session_id: unique identifier for this session
    - kyber_alg: the KEM algorithm used
    - public_key_b64: base64-encoded Kyber public key for client use
    """
    # Create a new Kyber KEM context for this session
    server_kem = oqs.KeyEncapsulation(KEM_ALG)
    public_key = server_kem.generate_keypair()

    # Generate a unique session ID to track this session
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "server_kem": server_kem,  # Store the KEM context until handshake completes
        "aes_key": None,           # Placeholder for the symmetric AES key to be derived
        "trust": 0.99,             # Initial trust value (demo purpose)
    }

    # Return session info and public key to client
    return jsonify({
        "session_id": session_id,
        "kyber_alg": KEM_ALG,
        "public_key_b64": base64.b64encode(public_key).decode("ascii"),
    })


@app.post("/session/handshake")
def session_handshake():
    """
    Complete the handshake by receiving the ciphertext from client,
    decapsulating it using the private Kyber key to obtain the shared secret,
    and then deriving an AES key from that secret using HKDF.
    
    Post-quantum cryptography usage:
    - Decapsulates the ciphertext sent by client using Kyber private key.
    - Derives a symmetric AES key bound to the session.
    
    Expects JSON payload with:
    - session_id: to identify the session
    - ciphertext_b64: base64-encoded Kyber ciphertext from client
    
    Returns:
    - status: handshake completion status
    - aes_key_len: length of derived AES key (for confirmation)
    """
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

    # Decapsulate to obtain the shared secret using Kyber private key
    shared_secret_server = server_kem.decap_secret(ciphertext)

    # Derive AES key using HKDF, binding the key to the session_id as context
    aes_key = hkdf_derive(shared_secret_server, info=session_id.encode("utf-8"), length=32)

    # Store derived AES key in session and dispose of KEM context to prevent reuse
    sess["aes_key"] = aes_key
    try:
        server_kem.close()
    except Exception:
        pass
    sess["server_kem"] = None

    return jsonify({"status": "ok", "aes_key_len": len(aes_key)})


@app.post("/session/update")
def session_update():
    """
    Receive encrypted data updates from the client.
    The client encrypts the payload with AES-GCM using the derived AES key.
    This endpoint decrypts the payload, parses the JSON, and updates trust score.
    
    AES-GCM decryption:
    - Uses stored AES key and provided nonce to decrypt ciphertext.
    - If decryption or JSON parsing fails, returns an error.
    
    Trust update:
    - This demo simply nudges the trust value down slightly.
    - In a real application, trust would be computed based on payload content.
    
    Expects JSON payload with:
    - session_id: to identify the session
    - nonce_b64: base64-encoded AES-GCM nonce
    - ciphertext_b64: base64-encoded AES-GCM ciphertext
    
    Returns:
    - status: ingestion status
    - received: decrypted payload
    - trust: updated trust value
    """
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
        # Decrypt ciphertext using AES-GCM with the stored key and provided nonce
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        # Parse decrypted plaintext JSON payload
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        # Return error if decryption or parsing fails
        return jsonify({"error": f"decrypt failed: {e}"}), 400

    # --- Demo: pretend to update trust based on payload ---
    # Here you would compute trust based on vectors. We'll nudge it slightly down.
    trust = max(0.0, min(1.0, sess.get("trust", 0.99) - 0.001))
    sess["trust"] = trust

    return jsonify({"status": "ingested", "received": payload, "trust": trust})


@app.get("/session/trust")
def session_trust():
    """
    Retrieve the current trust value for a given session.
    Query parameter:
    - session_id: the session to query
    
    Returns:
    - session_id
    - trust: current trust score (0.0 to 1.0)
    """
    session_id = request.args.get("session_id")
    sess = sessions.get(session_id)
    if not sess:
        return jsonify({"error": "unknown session"}), 404
    return jsonify({"session_id": session_id, "trust": sess.get("trust", 0.0)})


if __name__ == "__main__":
    # For local dev only. In prod, run with gunicorn/uvicorn behind TLS.
    app.run(host="0.0.0.0", port=8080, debug=True)