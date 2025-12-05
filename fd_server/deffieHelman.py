# diffie_helman.py
"""
Drop-in replacement for your original ECDH KeyExchangeHandler.
Public API kept identical:
  - class KeyExchangeHandler:
      - __init__(self)
      - public_key_bytes attribute (bytes)
      - derive_shared_key(other_user_public_key_bytes) -> bytes (32 bytes)

Behavior:
  - Default behavior is identical to your original ECDH (SECP384R1 + HKDF to 32 bytes).
  - If env var USE_PQ_KEM=1 and liboqs is installed, the module exposes PQKEMHelper utilities.
    However the KeyExchangeHandler keeps the ECDH behavior by default because KEM requires
    protocol changes (encapsulate/decapsulate) to be safe and symmetric.
  - If you want to adopt PQ KEM end-to-end, use the PQKEMHelper class below and update both
    client and server flows to perform encapsulation/decapsulation correctly.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# optional liboqs import for PQKEM helper
oqs = None
try:
    import oqs
except Exception:
    oqs = None

_USE_PQ_KEM = os.environ.get("USE_PQ_KEM", "0") == "1"


class KeyExchangeHandler:
    """
    ECDH-based key exchange (default). Matches your original API exactly.
    If you later want to switch to PQ KEM, replace this file or integrate PQKEMHelper
    with protocol changes.
    """

    def __init__(self):
        # Classical ECDH keys
        self._private_key = None
        self.public_key_bytes = None
        self._generate_keys()

    def _generate_keys(self):
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = self._private_key.public_key()
        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, other_user_public_key_bytes: bytes) -> bytes:
        """
        Derives a 32-byte AES key using ECDH + HKDF (SHA256).
        This implementation is identical to your original class for drop-in behavior.
        """
        if not self._private_key:
            raise ValueError("Private key not generated or loaded.")

        # Load the other user's public key from its byte representation (PEM)
        other_user_public_key = serialization.load_pem_public_key(other_user_public_key_bytes)

        # Perform the key exchange to get a raw shared secret
        shared_secret = self._private_key.exchange(ec.ECDH(), other_user_public_key)

        # Use a Key Derivation Function (HKDF) to turn the raw secret into a strong,
        # fixed-length key suitable for AES encryption.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits for AES-256
            salt=None,
            info=b'federated-learning-shared-key',  # context
        ).derive(shared_secret)

        return derived_key


# --------------------------
# PQ KEM helper (explicit API)
# --------------------------
# This helper class provides explicit encapsulate / decapsulate methods for Kyber KEMs.
# Use these methods only if you change the protocol to have one side encapsulate and the other decapsulate.
# It is NOT wired into KeyExchangeHandler. This file intentionally keeps the KeyExchangeHandler ECDH
# for backward compatibility and correct symmetric behavior.
#
# If you want to switch to PQ KEM for real:
#  - Both sides must agree who encapsulates and who decapsulates (or implement a deterministic policy).
#  - Use PQKEMHelper.generate_keypair(), PQKEMHelper.encapsulate(pk) and other.decapsulate(sk, ct)
#  - Derive AES key from KEM shared secret via HKDF (examples below).
#
if oqs is not None and _USE_PQ_KEM:
    class PQKEMHelper:
        """
        Helper for Kyber KEM operations using liboqs.
        Methods:
          - generate_keypair() -> (public_key_bytes, secret_key_bytes)
          - encapsulate(public_key_bytes) -> (ciphertext, shared_secret)
          - decapsulate(secret_key_bytes, ciphertext) -> shared_secret
        The shared_secret bytes should be converted into an AES key via HKDF as needed.
        """
        def __init__(self, kem_alg: str = None):
            available = oqs.get_enabled_kem_mechanisms()
            if not available:
                raise RuntimeError("No KEM mechanisms enabled in liboqs on this system.")
            preferred = ["Kyber768", "Kyber512", "Kyber1024"]
            if kem_alg is None:
                chosen = None
                for p in preferred:
                    if p in available:
                        chosen = p
                        break
                if chosen is None:
                    chosen = available[0]
            else:
                if kem_alg not in available:
                    raise ValueError(f"Requested KEM {kem_alg} not available. Enabled: {available}")
                chosen = kem_alg
            self.alg = chosen

        def generate_keypair(self):
            kem = oqs.KeyEncapsulation(self.alg)
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            kem.free()
            return pk, sk

        def encapsulate(self, public_key_bytes: bytes):
            kem = oqs.KeyEncapsulation(self.alg)
            kem.import_public_key(public_key_bytes)
            ct, shared_secret = kem.encap_secret()
            kem.free()
            return ct, shared_secret

        def decapsulate(self, secret_key_bytes: bytes, ciphertext: bytes):
            kem = oqs.KeyEncapsulation(self.alg)
            kem.import_secret_key(secret_key_bytes)
            ss = kem.decap_secret(ciphertext)
            kem.free()
            return ss

        @staticmethod
        def kdf_to_aes_key(shared_secret: bytes, length: int = 32):
            """
            Turn shared_secret bytes into an AES key of `length` bytes using HKDF-SHA256.
            """
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            dk = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b'pq-kem-to-aes').derive(shared_secret)
            return dk
else:
    # Provide a stub with helpful message if PQ KEM not enabled or liboqs missing
    class PQKEMHelper:
        def __init__(self, *args, **kwargs):
            raise ImportError("PQ KEM helper unavailable: liboqs not found or USE_PQ_KEM not set. "
                              "Install liboqs and set env USE_PQ_KEM=1 to enable.")
