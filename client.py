import base64, json, os, sys
import requests
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = "http://127.0.0.1:8080"
KEM_ALG = "Kyber512"
HKDF_SALT = b"TrustGraphDemoSalt"


def hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=HKDF_SALT, info=info)
    return hkdf.derive(key_material)


def main():
    # 1) Start a session, fetch Kyber public key
    r = requests.post(f"{BASE}/session/start")
    r.raise_for_status()
    s = r.json()
    session_id = s["session_id"]
    pubkey = base64.b64decode(s["public_key_b64"])
    print("[client] session:", session_id)

    # 2) Encapsulate using server public key
    with oqs.KeyEncapsulation(KEM_ALG) as client_kem:
        ciphertext, shared_secret_client = client_kem.encap_secret(pubkey)

    # 3) Send ciphertext to server to finish handshake
    r = requests.post(f"{BASE}/session/handshake", json={
        "session_id": session_id,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    })
    r.raise_for_status()
    print("[client] handshake status:", r.json())

    # 4) Derive the same AES key client-side
    aes_key = hkdf_derive(shared_secret_client, info=session_id.encode("utf-8"), length=32)

    # 5) Encrypt a demo payload and send to /session/update
    payload = {
        "ts": "demo",
        "vectors": [
            {"v": 0.42, "a": 0.1, "j": 0.003},
            {"v": 0.51, "a": 0.12, "j": 0.004},
        ],
    }
    plaintext = json.dumps(payload).encode("utf-8")
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    r = requests.post(f"{BASE}/session/update", json={
        "session_id": session_id,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    })
    r.raise_for_status()
    print("[client] update response:", r.json())

    # 6) Fetch current trust value
    r = requests.get(f"{BASE}/session/trust", params={"session_id": session_id})
    r.raise_for_status()
    print("[client] trust:", r.json())


if __name__ == "__main__":
    sys.exit(main())