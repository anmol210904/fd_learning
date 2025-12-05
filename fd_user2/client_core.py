# client_core.py
"""
ClientCore: trimmed so terminal remains minimal.

Methods return decoded global-integers for the run_client to decode and print floats.
Detailed debug logs remain in client_verbose.log (via logger.debug).
"""

import json
import logging
import random
from typing import List, Tuple, Optional

from config import PRECISION_FACTOR, PUBLIC_VECTOR_A
from vector_model import VectorModel
from apiclient import APIClient
from utils_crypto import AESCipher, b64e, b64d

from diffie_helman import KeyExchangeHandler
from digital_signature import SignatureHandler
from shamirClass import VectorShamirSecretSharing

logger = logging.getLogger("client_core")
logger.setLevel(logging.DEBUG)  # file will get debug

class ClientCore:
    def __init__(self, model: VectorModel, api_client: APIClient):
        self.model = model
        self.api = api_client
        self.token = None

        # crypto helpers
        self.signature = SignatureHandler()
        self.dh = KeyExchangeHandler()
        self.shamir = VectorShamirSecretSharing()

        # mapping token -> AESCipher for pairwise encryption
        self.shared_keys = {}
        self.num_participants = 0

    # -------------------------
    # Registration & key exchange
    # -------------------------
    def register(self) -> int:
        pk_b64 = b64e(self.dh.public_key_bytes)
        sig = self.signature.sign_message(self.dh.public_key_bytes)
        sig_b64 = b64e(sig)
        dsapk_b64 = b64e(self.signature.public_key_bytes)

        token = self.api.register_user(pk_b64, sig_b64, dsapk_b64)
        self.token = int(token)
        logger.debug("Registered with server: token=%s", self.token)
        return self.token

    def fetch_users_and_establish_keys(self) -> int:
        users = self.api.get_users(self.token)
        self.num_participants = len(users)
        logger.debug("Group size reported by server: %s", self.num_participants)

        for i, u in enumerate(users):
            recipient_token = i + 1
            if recipient_token == self.token:
                continue
            other_pk = b64d(u["public_key"])
            shared_key = self.dh.derive_shared_key(other_pk)
            self.shared_keys[recipient_token] = AESCipher(shared_key)
            logger.debug("Derived shared key for user %s", recipient_token)

        return self.num_participants

    # -------------------------
    # Initial model fetch
    # -------------------------
    def fetch_initial_model(self) -> bool:
        """
        Fetch the initial model (window 0). Decode signed modular integers
        returned by server into floats and load into local model.
        """
        resp = self.api.get_initial_model()
        enc = resp.get("global_model_weights", [])
        if not enc:
            logger.debug("No initial model available from server.")
            return False

        try:
            prime = self.shamir.PRIME
            half = prime // 2

            def _decode_signed_int(value: int) -> int:
                v = int(value) % prime
                if v > half:
                    return v - prime
                return v

            decoded_signed = [_decode_signed_int(int(v)) for v in enc]
            decoded_floats = [s / PRECISION_FACTOR for s in decoded_signed]

            self.model.set_flat_weights(decoded_floats)
            logger.debug("Initial model loaded into local model (signed decode).")
            return True
        except Exception as e:
            logger.exception("Failed to load initial model: %s", e)
            return False


    # -------------------------
    # Share preparation & exchange
    # -------------------------
    def _encode_flat_weights(self, flat: List[float]) -> List[int]:
        return [int(x * PRECISION_FACTOR) % self.shamir.PRIME for x in flat]

    def prepare_and_send_shares(self) -> Tuple[List[int], List[int]]:
        flat = self.model.get_flat_weights()
        encoded_weights = self._encode_flat_weights(flat)

        # Only debug to file
        logger.debug("Local float weights (first 20): %s", flat[:20])
        logger.debug("Encoded weights (first 20): %s", encoded_weights[:20])

        mask = [random.randint(0, self.shamir.PRIME - 1) for _ in range(len(encoded_weights))]
        shares = self.shamir.split_secret(mask, self.num_participants, self.num_participants)

        encrypted_shares_b64 = []
        for i in range(self.num_participants):
            recipient = i + 1
            share_vector = shares[i][1]
            share_bytes = json.dumps(share_vector).encode("utf-8")
            if recipient == self.token:
                encrypted_shares_b64.append(b64e(share_bytes))
            else:
                cipher = self.shared_keys.get(recipient)
                if cipher is None:
                    raise RuntimeError(f"No shared AES key for recipient {recipient}")
                ct = cipher.encrypt(share_bytes)
                encrypted_shares_b64.append(b64e(ct))

        logger.debug("Prepared encrypted shares payload (first 3 entries shown): %s", encrypted_shares_b64[:3])

        # send to server (window 3)
        self.api.submit_shamir_shares(self.token, encrypted_shares_b64)
        logger.debug("Shamir shares submitted to server.")
        return encoded_weights, mask

    def receive_and_sum_shares(self) -> List[int]:
        resp = self.api.get_shamir_shares(self.token)
        shares_b64 = resp.get("shares", [])
        if not shares_b64:
            raise RuntimeError("No shares returned by server for this user.")

        decrypted_vectors = []
        for i, enc_b64 in enumerate(shares_b64):
            sender = i + 1
            enc_bytes = b64d(enc_b64)
            if sender == self.token:
                decrypted_vectors.append(json.loads(enc_bytes.decode("utf-8")))
            else:
                cipher = self.shared_keys.get(sender)
                if cipher is None:
                    raise RuntimeError(f"No shared key for decrypting sender {sender}")
                plain = cipher.decrypt(enc_bytes)
                decrypted_vectors.append(json.loads(plain.decode("utf-8")))

        summed = [sum(col) % self.shamir.PRIME for col in zip(*decrypted_vectors)]
        logger.debug("Summed shares computed (first 20): %s", summed[:20])
        return summed

    def submit_final_data(self, encoded_weights: List[int], mask: List[int], summed_shares: List[int]) -> None:
        if len(encoded_weights) != len(mask):
            raise ValueError("encoded_weights and mask length mismatch")

        masked_weights = [ (w + m) % self.shamir.PRIME for w, m in zip(encoded_weights, mask) ]
        verification_tag = [ ( ( (int(a) % self.shamir.PRIME) * w ) + m ) % self.shamir.PRIME
                             for a, w, m in zip(PUBLIC_VECTOR_A, encoded_weights, mask) ]

        # Log full payloads to verbose file only
        logger.debug("Submitting summed_shares (first 20): %s", summed_shares[:20])
        logger.debug("Submitting masked_weights (first 20): %s", masked_weights[:20])
        logger.debug("Submitting verification_tag (first 20): %s", verification_tag[:20])

        self.api.submit_summed_shares(self.token, summed_shares)
        self.api.submit_data(self.token, masked_weights, verification_tag)
        logger.debug("Submitted summed shares and masked weights + verification tag to server.")

    def fetch_and_update_global(self) -> Tuple[bool, Optional[List[int]]]:
        """
        Returns (success, global_ints) so run_client can decode floats for terminal.
        """
        resp = self.api.get_global_model()
        enc_global = resp.get("global_model_weights", [])
        enc_agg_tag = resp.get("aggrigated_tag", [])

        if not enc_global or not enc_agg_tag:
            logger.error("Server returned empty global model or aggregated tag.")
            return False, None

        global_ints = [int(x) % self.shamir.PRIME for x in enc_global]
        agg_tag_ints = [int(x) % self.shamir.PRIME for x in enc_agg_tag]

        prime = self.shamir.PRIME
        expected_tag_ints = [ ( (int(a) % prime) * g ) % prime for a, g in zip(PUBLIC_VECTOR_A, global_ints) ]

        mismatches = []
        for i, (et, at) in enumerate(zip(expected_tag_ints, agg_tag_ints)):
            if (et - at) % prime != 0:
                mismatches.append((i, et, at))
                if len(mismatches) >= 10:
                    break

        if mismatches:
            logger.error("Verification FAILED (modular integer comparison). Sample mismatches: %s", mismatches[:10])
            return False, global_ints

        def _decode_signed(value: int) -> int:
            half = prime // 2
            if value > half:
                return value - prime
            return value

        decoded_signed = [_decode_signed(v) for v in global_ints]
        decoded_floats = [s / PRECISION_FACTOR for s in decoded_signed]

        # Write final results to verbose log
        logger.debug("FINAL GLOBAL: global_ints (first 20): %s", global_ints[:20])
        logger.debug("FINAL GLOBAL: decoded_floats (first 20): %s", decoded_floats[:20])

        try:
            self.model.set_flat_weights(decoded_floats)
            logger.debug("Verification SUCCESS — updated local model weights.")
            return True, global_ints
        except Exception as e:
            logger.exception("Failed to set decoded global weights into model: %s", e)
            return False, global_ints
