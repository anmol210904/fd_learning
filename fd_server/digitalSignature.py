# digitalSignature.py
"""
Drop-in replacement for your original ECDSA SignatureHandler.
Public API kept identical:
  - class SignatureHandler:
      - __init__(self)
      - sign_message(self, message: bytes) -> bytes
      - @staticmethod verify_signature(public_key_bytes, message, signature) -> bool

Behavior:
  - By default (no env var), uses classical ECDSA (cryptography library).
  - If env var USE_PQ_SIG=1 AND liboqs Python bindings are installed, uses a PQ signature
    (Dilithium variant) while preserving the same API.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Try to import liboqs (optional post-quantum backend)
_try_import_oqs = True
oqs = None
if _try_import_oqs:
    try:
        import oqs  # liboqs Python bindings; may be named 'oqs'
    except Exception:
        oqs = None

_USE_PQ = os.environ.get("USE_PQ_SIG", "0") == "1"


class SignatureHandler:
    """
    Signature handler that uses ECDSA by default, or Dilithium via liboqs if enabled.
    The public API and method names are identical to your original class.
    """

    def __init__(self):
        # Decide whether PQ mode is active
        self._pq_mode = _USE_PQ
        if self._pq_mode and oqs is None:
            raise ImportError(
                "Post-quantum mode requested (USE_PQ_SIG=1) but liboqs Python bindings are not available. "
                "Install liboqs and the Python wrapper (e.g., liboqs + liboqs-python) to use PQ signatures."
            )

        if self._pq_mode:
            # Initialize Dilithium keypair using liboqs
            # Choose a sensible default (Dilithium3 preferred)
            enabled = oqs.get_enabled_sig_mechanisms()
            preferred = ["Dilithium3", "Dilithium2", "Dilithium5"]
            chosen = None
            for p in preferred:
                if p in enabled:
                    chosen = p
                    break
            if chosen is None:
                chosen = enabled[0]
            self._pq_alg = chosen
            signer = oqs.Signature(self._pq_alg)
            # some wrappers: generate_keypair returns pk, sk; others store internally and provide export
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            signer.free()
            self.public_key_bytes = pk
            self._secret_key_bytes = sk
            # keep a note for debugging
            self._impl = "pq-dilithium:" + self._pq_alg
        else:
            # Classical ECDSA initialization (same as your original)
            self._private_key = None
            self.public_key_bytes = None
            self._generate_keys()
            self._impl = "ecdsa-secp384r1"

    # ---------------- classical ECDSA methods (identical to original) ----------------
    def _generate_keys(self):
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        pub = self._private_key.public_key()
        self.public_key_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message: bytes) -> bytes:
        """
        Sign a message. If PQ mode active, use Dilithium; else use ECDSA.
        Returns signature bytes.
        """
        if self._pq_mode:
            # PQ sign using liboqs
            with oqs.Signature(self._pq_alg) as s:
                s.import_secret_key(self._secret_key_bytes)
                sig = s.sign(message)
                return sig
        else:
            if not self._private_key:
                raise ValueError("Private key not generated or loaded.")
            return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    @staticmethod
    def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify signature. Tries PQ verification first if liboqs is available and env var set,
        else falls back to classical ECDSA verification (assumes PEM format).
        """
        # If PQ mode requested and oqs available, try PQ verify using candidate Dilithium algs
        use_pq = _USE_PQ and (oqs is not None)
        if use_pq:
            enabled = oqs.get_enabled_sig_mechanisms()
            # prefer common Dilithium variants
            candidates = [c for c in ["Dilithium3", "Dilithium2", "Dilithium5"] if c in enabled] + [c for c in enabled if c not in ["Dilithium3", "Dilithium2", "Dilithium5"]]
            for alg in candidates:
                try:
                    with oqs.Signature(alg) as verifier:
                        verifier.import_public_key(public_key_bytes)
                        try:
                            return verifier.verify(message, signature)
                        except Exception:
                            continue
                except Exception:
                    continue
            # PQ verification failed across candidates -> return False
            return False

        # Fallback classical ECDSA verification (identical to original)
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            # keep behavior similar to original (print unexpected error)
            print(f"An unexpected error occurred during verification: {e}")
            return False
