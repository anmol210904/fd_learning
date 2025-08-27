from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class KeyExchangeHandler:
    """
    A class to handle Elliptic Curve Diffie-Hellman (ECDH) key exchange.
    Each instance represents a user with their own key pair, capable of deriving
    shared secrets with other users.
    """
    def __init__(self):
        """
        Initializes the handler by generating a new ECDH key pair.
        """
        # --- PRIVATE / SECRET DATA ---
        self._private_key = None
        
        # --- PUBLIC DATA ---
        self.public_key_bytes = None
        
        self._generate_keys()

    def _generate_keys(self):
        """
        Generates an ECDH key pair and stores them as instance variables.
        """
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = self._private_key.public_key()
        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, other_user_public_key_bytes):
        """
        Derives a shared symmetric key (for AES) using the instance's private key
        and another user's public key.

        Args:
            other_user_public_key_bytes (bytes): The public key from the other user.

        Returns:
            bytes: A 32-byte (256-bit) shared key suitable for symmetric encryption.
        """
        if not self._private_key:
            raise ValueError("Private key not generated or loaded.")

        # Load the other user's public key from its byte representation
        other_user_public_key = serialization.load_pem_public_key(
            other_user_public_key_bytes
        )

        # Perform the key exchange to get a raw shared secret
        shared_secret = self._private_key.exchange(ec.ECDH(), other_user_public_key)

        # Use a Key Derivation Function (HKDF) to turn the raw secret into a strong,
        # fixed-length key suitable for AES encryption.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits for AES-256
            salt=None,
            info=b'federated-learning-shared-key', # A context string
        ).derive(shared_secret)
        
        return derived_key
