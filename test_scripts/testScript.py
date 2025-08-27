import requests
import json
import random
import base64
import time
import logging
import os
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# --- CONFIGURATION ---
SERVER_URL = "http://3.6.94.252:80"
VECTOR_SIZE = 10
PRECISION_FACTOR = 10**6
# This public vector 'a' must be known by both the server and all clients.
PUBLIC_VECTOR_A = [random.randint(1, 10) for _ in range(VECTOR_SIZE)]

# --- CRYPTOGRAPHIC AND UTILITY CLASSES ---

class SignatureHandler:
    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    def sign_message(self, message):
        return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))

class KeyExchangeHandler:
    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    def derive_shared_key(self, other_user_public_key_bytes):
        other_user_public_key = serialization.load_pem_public_key(other_user_public_key_bytes)
        shared_secret = self._private_key.exchange(ec.ECDH(), other_user_public_key)
        return HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'federated-learning-shared-key'
        ).derive(shared_secret)

class AESCipher:
    def __init__(self, key):
        self.key = key
    def encrypt(self, plaintext_bytes):
        nonce = os.urandom(12)
        aead = AESGCM(self.key)
        ciphertext = aead.encrypt(nonce, plaintext_bytes, None)
        return nonce + ciphertext
    def decrypt(self, ciphertext_with_nonce):
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]
        aead = AESGCM(self.key)
        return aead.decrypt(nonce, ciphertext, None)

class VectorShamirSecretSharing:
    def __init__(self):
        self.PRIME = 2**521 - 1
    def _evaluate_polynomial(self, coeffs, x):
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % self.PRIME
        return result
    def split_secret(self, secret_vector, num_shares, threshold):
        shares = [[] for _ in range(num_shares)]
        for secret_element in secret_vector:
            coeffs = [secret_element] + [random.randint(0, self.PRIME - 1) for _ in range(threshold - 1)]
            for i in range(1, num_shares + 1):
                shares[i-1].append(self._evaluate_polynomial(coeffs, i))
        return shares

# --- USER CLASS ---

class User:
    def __init__(self, user_id):
        self.user_id = user_id
        self.token = None
        self.signature_handler = SignatureHandler()
        self.dh_handler = KeyExchangeHandler()
        self.shamir_handler = VectorShamirSecretSharing()
        self.shared_keys = {}
        self.num_participants = 0
        self.original_weights = []

    def register(self):
        signature = self.signature_handler.sign_message(self.dh_handler.public_key_bytes)
        payload = {
            "publicKey": base64.b64encode(self.dh_handler.public_key_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "DSAPK": base64.b64encode(self.signature_handler.public_key_bytes).decode('utf-8')
        }
        response = requests.post(f"{SERVER_URL}/registerUser", json=payload)
        response.raise_for_status()
        self.token = int(response.json()['userToken'])

    def fetch_and_establish_keys(self):
        response = requests.get(f"{SERVER_URL}/getUser/{self.token}")
        response.raise_for_status()
        all_users_data = response.json()['users']
        self.num_participants = len(all_users_data)
        for i, user_data in enumerate(all_users_data):
            other_user_token = i + 1
            if other_user_token == self.token: continue
            dh_pk_bytes = base64.b64decode(user_data['public_key'])
            shared_key = self.dh_handler.derive_shared_key(dh_pk_bytes)
            self.shared_keys[other_user_token] = AESCipher(shared_key)

    def submit_mask_shares(self):
        mask = [random.randint(0, 100) for _ in range(VECTOR_SIZE)]
        shares = self.shamir_handler.split_secret(mask, self.num_participants, self.num_participants)
        encrypted_shares_payload = []
        for i in range(self.num_participants):
            recipient_token = i + 1
            share_vector_json = json.dumps(shares[i]).encode('utf-8')
            if recipient_token == self.token:
                encrypted_shares_payload.append(base64.b64encode(share_vector_json).decode('utf-8'))
            else:
                encrypted_share = self.shared_keys[recipient_token].encrypt(share_vector_json)
                encrypted_shares_payload.append(base64.b64encode(encrypted_share).decode('utf-8'))
        payload = {"token": self.token, "shares": encrypted_shares_payload}
        requests.post(f"{SERVER_URL}/submit_shamir_shares", json=payload).raise_for_status()
        return mask

    def receive_and_decrypt_shares(self):
        payload = {"token": self.token}
        response = requests.post(f"{SERVER_URL}/get_shamir_shares", json=payload)
        response.raise_for_status()
        received_encrypted_shares = response.json()['shares']
        decrypted_shares = []
        for i, enc_share_b64 in enumerate(received_encrypted_shares):
            sender_token = i + 1
            enc_share_bytes = base64.b64decode(enc_share_b64)
            if sender_token == self.token:
                decrypted_shares.append(json.loads(enc_share_bytes.decode('utf-8')))
            else:
                decrypted_share_json = self.shared_keys[sender_token].decrypt(enc_share_bytes)
                decrypted_shares.append(json.loads(decrypted_share_json.decode('utf-8')))
        return decrypted_shares

    def submit_all_final_data(self, decrypted_shares, mask):
        summed_shares = [0] * VECTOR_SIZE
        for share_vector in decrypted_shares:
            for i in range(VECTOR_SIZE):
                summed_shares[i] = (summed_shares[i] + share_vector[i]) % self.shamir_handler.PRIME
        payload_summed = {"token": self.token, "summed_shares": summed_shares}
        requests.post(f"{SERVER_URL}/submit_summed_shares", json=payload_summed).raise_for_status()
        
        self.original_weights = [random.uniform(0.0, 1.0) for _ in range(VECTOR_SIZE)]
        encoded_weights = [int(w * PRECISION_FACTOR) for w in self.original_weights]
        masked_weights = [(w + m) for w, m in zip(encoded_weights, mask)]
        # The user creates the verification tag using the public vector 'a'
        # Corrected formula: (a * w) + m
        verification_tag = [(a * w + m) for a, w, m in zip(PUBLIC_VECTOR_A, encoded_weights, mask)]
        payload_data = {"token": self.token, "masked_weights": masked_weights, "verification_tags": verification_tag}
        requests.post(f"{SERVER_URL}/submit_data", json=payload_data).raise_for_status()

    def fetch_and_verify_global_model(self):
        logging.info(f"--- User {self.user_id}: Fetching and verifying global model ---")
        
        url = f"{SERVER_URL}/get_global_model"
        logging.info(f"User {self.user_id}: Making GET request to {url}")
        
        response = requests.get(url)
        
        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()
        
        response_data = response.json()

        global_model_encoded = response_data.get('global_model_weights', [])
        aggregated_tag_encoded = response_data.get('aggrigated_tag', [])

        if not global_model_encoded or not aggregated_tag_encoded:
            logging.warning(f"User {self.user_id}: Global model or tag was empty.")
            return

        # Decode both the model and the tag back to floats
        global_model_decoded = [w / PRECISION_FACTOR for w in global_model_encoded]
        aggregated_tag_decoded = [t / PRECISION_FACTOR for t in aggregated_tag_encoded]
        
        logging.info(f"User {self.user_id}: Decoded Global Model: {[round(w, 4) for w in global_model_decoded]}")
        logging.info(f"User {self.user_id}: Decoded Aggregated Tag from Server: {[round(t, 4) for t in aggregated_tag_decoded]}")

        # --- PERFORM VERIFICATION ---
        # Locally compute what the tag SHOULD be, based on the received global model
        expected_tag = [a * w for a, w in zip(PUBLIC_VECTOR_A, global_model_decoded)]
        logging.info(f"User {self.user_id}: Locally Calculated Expected Tag: {[round(t, 4) for t in expected_tag]}")

        # Compare the server's tag with the locally computed one (using a tolerance for float math)
        if np.allclose(aggregated_tag_decoded, expected_tag, atol=1e-5):
            logging.info("✅ VERIFICATION SUCCESSFUL: The server's aggregation is correct.")
        else:
            logging.error("❌ VERIFICATION FAILED: The server's aggregation is incorrect or was tampered with.")

def perform_action_with_retry(action_function, action_name):
    """Handles 'Wrong Window' errors by waiting and retrying automatically."""
    logging.info(f"Attempting to perform: {action_name}")
    while True:
        try:
            result = action_function()
            logging.info(f"Successfully completed: {action_name}")
            return result
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400 and ('Wrong' in e.response.text or 'not open' in e.response.text):
                logging.warning(f"Server not in correct window for '{action_name}'. Waiting 10 seconds to retry...")
                time.sleep(10)
            else:
                logging.error(f"An unexpected HTTP error occurred for {action_name}: {e.response.text}")
                raise
        except requests.exceptions.RequestException as e:
            logging.error(f"A network error occurred for {action_name}: {e}")
            raise

def main():
    """Orchestrates the simulation for a single autonomous user."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    user = User(user_id=random.randint(100, 999))
    while True:
        logging.info("\n\n=============== STARTING NEW ROUND PARTICIPATION ===============")
        try:
            perform_action_with_retry(user.register, "Registration")
            perform_action_with_retry(user.fetch_and_establish_keys, "Key Exchange")
            mask = perform_action_with_retry(user.submit_mask_shares, "Submit Mask Shares")
            decrypted_shares = perform_action_with_retry(user.receive_and_decrypt_shares, "Receive Mask Shares")
            perform_action_with_retry(lambda: user.submit_all_final_data(decrypted_shares, mask), "Submit All Final Data")
            perform_action_with_retry(user.fetch_and_verify_global_model, "Fetch and Verify Global Model")
            logging.info("=============== ROUND COMPLETE, WAITING FOR NEXT ===============")
            time.sleep(30)
        except Exception as e:
            logging.error(f"A critical error occurred: {e}. Restarting after 30 seconds.")
            time.sleep(30)

if __name__ == "__main__":
    main()
