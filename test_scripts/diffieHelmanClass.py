import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class DiffieHellmanUser:
    """
    A class to represent a user in a Diffie-Hellman key exchange.

    This class handles the generation of private/public key pairs and the
    derivation of a shared secret key using another party's public key.
    The exchange uses Elliptic Curve Diffie-Hellman (ECDH).
    """

    def __init__(self):
        """
        Initializes a new user by generating a private key.
        The corresponding public key is derived from the private key.
        """
        # Generate a private key using the SECP384R1 elliptic curve.
        # This is a standard, widely-used curve that offers a high level of security.
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self._private_key.public_key()
        self.shared_key = None

    def get_public_key_bytes(self) -> bytes:
        """
        Serializes the public key into bytes for transmission.

        Returns:
            bytes: The public key in PEM format, which is a standard way
                   to encode cryptographic keys.
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, peer_public_key_bytes: bytes):
        """
        Derives a shared secret key using the peer's public key.

        This method performs the core ECDH exchange. The resulting shared secret
        is then passed through a Key Derivation Function (HKDF) to produce a
        cryptographically strong key suitable for symmetric encryption.

        Args:
            peer_public_key_bytes (bytes): The serialized public key received
                                           from the other user.
        """
        # Load the peer's public key from its byte representation.
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)

        # Perform the key exchange to get a shared secret.
        shared_secret = self._private_key.exchange(ec.ECDH(), peer_public_key)

        # Use HKDF to derive a robust 32-byte (256-bit) key from the shared secret.
        # This is a crucial step to ensure the final key is uniformly random.
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None, # A salt is optional but recommended in real applications.
            info=b'diffie-hellman-shared-key-example',
        ).derive(shared_secret)
        print(f"Derived a shared key: {self.shared_key.hex()}")

