from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

class SignatureHandler:
    """
    A class to handle ECDSA key generation, signing, and verification.
    Each instance of this class represents a user with their own key pair.
    """
    def __init__(self):
        """
        Initializes the handler by generating a new ECDSA key pair.
        """
        # --- PRIVATE / SECRET DATA ---
        # The private key is stored as a "private" attribute.
        self._private_key = None
        
        # --- PUBLIC DATA ---
        # The public key bytes can be safely shared with others.
        self.public_key_bytes = None
        
        self._generate_keys()

    def _generate_keys(self):
        """
        Generates an ECDSA key pair and stores them as instance variables.
        """
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = self._private_key.public_key()
        self.public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message):
        """
        Signs a message using the instance's private key.

        Args:
            message (bytes): The message to be signed. Must be in bytes.

        Returns:
            bytes: The digital signature.
        """
        if not self._private_key:
            raise ValueError("Private key not generated or loaded.")
            
        return self._private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

    @staticmethod
    def verify_signature(public_key_bytes, message, signature):
        """
        Verifies a signature against a message and a public key.
        This is a static method because anyone with the public key can verify,
        without needing an instance of the class.

        Args:
            public_key_bytes (bytes): The public key of the signer.
            message (bytes): The original message that was signed.
            signature (bytes): The signature to verify.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"An unexpected error occurred during verification: {e}")
            return False

