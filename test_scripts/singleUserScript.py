import requests
import json
import random
import base64
import time
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# --- CONFIGURATION ---
SERVER_URL = "http://127.0.0.1:5000"
VECTOR_SIZE = 10
PRECISION_FACTOR = 10**6 # For encoding floats to integers

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
    @staticmethod
    def verify_signature(public_key_bytes, message, signature):
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

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
        nonce = random.getrandbits(96).to_bytes(12, 'big')
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
        self.num_participants = 0 # Will be set dynamically
        self.original_weights = [] # To store the original float weights for verification

    def register(self):
        logging.info(f"--- User {self.user_id}: Registering with server ---")
        signature = self.signature_handler.sign_message(self.dh_handler.public_key_bytes)
        payload = {
            "publicKey": base64.b64encode(self.dh_handler.public_key_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "DSAPK": base64.b64encode(self.signature_handler.public_key_bytes).decode('utf-8')
        }
        response = requests.post(f"{SERVER_URL}/registerUser", json=payload)
        response.raise_for_status()
        response_data = response.json()
        self.token = int(response_data['userToken'])
        logging.info(f"User {self.user_id}: Registration successful. Received token: {self.token}")

    def fetch_and_establish_keys(self):
        logging.info(f"--- User {self.user_id}: Fetching public keys of other users ---")
        response = requests.get(f"{SERVER_URL}/getUser/{self.token}")
        response.raise_for_status()
        all_users_data = response.json()['users']
        
        self.num_participants = len(all_users_data)
        logging.info(f"User {self.user_id}: Determined there are {self.num_participants} participants in this round.")

        for i, user_data in enumerate(all_users_data):
            other_user_token = i + 1
            if other_user_token == self.token: continue
            dh_pk_bytes = base64.b64decode(user_data['public_key'])
            shared_key = self.dh_handler.derive_shared_key(dh_pk_bytes)
            self.shared_keys[other_user_token] = AESCipher(shared_key)
            logging.info(f"User {self.user_id}: Established shared AES key with user {other_user_token}")

    def submit_mask_shares(self):
        logging.info(f"--- User {self.user_id}: Generating and submitting mask shares ---")
        mask = [random.randint(0, 100) for _ in range(VECTOR_SIZE)]
        logging.info(f"User {self.user_id}: Generated original mask: {mask}")
        
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
        logging.info(f"User {self.user_id}: Submitted encrypted shares successfully.")
        return mask

    def receive_and_decrypt_shares(self):
        logging.info(f"--- User {self.user_id}: Fetching and decrypting my shares ---")
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
        logging.info(f"User {self.user_id}: Successfully decrypted all received shares.")
        return decrypted_shares

    def submit_all_final_data(self, decrypted_shares, mask):
        logging.info(f"--- User {self.user_id}: Preparing and submitting all final data ---")
        # 1. Submit summed shares
        summed_shares = [0] * VECTOR_SIZE
        for share_vector in decrypted_shares:
            for i in range(VECTOR_SIZE):
                summed_shares[i] = (summed_shares[i] + share_vector[i]) % self.shamir_handler.PRIME
        payload_summed = {"token": self.token, "summed_shares": summed_shares}
        requests.post(f"{SERVER_URL}/submit_summed_shares", json=payload_summed).raise_for_status()
        logging.info(f"User {self.user_id}: Submitted summed shares successfully.")
        
        # 2. Submit masked weights and tag
        self.original_weights = [random.uniform(0.0, 1.0) for _ in range(VECTOR_SIZE)]
        logging.info(f"User {self.user_id}: Generated original weights: {[round(w, 4) for w in self.original_weights]}")
        
        encoded_weights = [int(w * PRECISION_FACTOR) for w in self.original_weights]
        masked_weights = [(w + m) for w, m in zip(encoded_weights, mask)]
        verification_tag = [(w * 2 + m) for w, m in zip(encoded_weights, mask)]
        payload_data = {"token": self.token, "masked_weights": masked_weights, "verification_tags": verification_tag}
        requests.post(f"{SERVER_URL}/submit_data", json=payload_data).raise_for_status()
        logging.info(f"User {self.user_id}: Submitted masked weights and tag successfully.")

    def fetch_global_model(self):
        logging.info(f"--- User {self.user_id}: Fetching global model ---")
        response = requests.get(f"{SERVER_URL}/get_global_model")
        response.raise_for_status()
        response_data = response.json()
        global_model_encoded = response_data['global_model_weights']
        if not global_model_encoded:
            logging.warning(f"User {self.user_id}: Global model is empty.")
            return
        global_model_decoded = [w / PRECISION_FACTOR for w in global_model_encoded]
        logging.info(f"User {self.user_id}: Final decoded global model: {[round(w, 4) for w in global_model_decoded]}")

def perform_action_with_retry(action_function, action_name):
    """
    Continuously tries to perform an action until it succeeds.
    Handles 'Wrong Window' errors by waiting and retrying.
    """
    logging.info(f"Attempting to perform: {action_name}")
    while True:
        try:
            result = action_function()
            logging.info(f"Successfully completed: {action_name}")
            return result
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400 and 'Wrong' in e.response.text:
                logging.warning(f"Server not in correct window for '{action_name}'. Waiting 10 seconds to retry...")
                time.sleep(10)
            else:
                logging.error(f"An unexpected HTTP error occurred for {action_name}: {e.response.text}")
                raise
        except requests.exceptions.RequestException as e:
            logging.error(f"A network error occurred for {action_name}: {e}")
            raise

def main():
    """Orchestrates the entire simulation for a single autonomous user."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    user = User(user_id=random.randint(100, 999))

    while True: # Main loop to continuously participate in rounds
        logging.info("\n\n=============== STARTING NEW ROUND PARTICIPATION ===============")
        try:
            perform_action_with_retry(user.register, "Registration")
            perform_action_with_retry(user.fetch_and_establish_keys, "Key Exchange")
            mask = perform_action_with_retry(user.submit_mask_shares, "Submit Mask Shares")
            decrypted_shares = perform_action_with_retry(user.receive_and_decrypt_shares, "Receive Mask Shares")
            perform_action_with_retry(lambda: user.submit_all_final_data(decrypted_shares, mask), "Submit All Final Data")
            perform_action_with_retry(user.fetch_global_model, "Fetch Global Model")
            logging.info("=============== ROUND COMPLETE, WAITING FOR NEXT ===============")
            time.sleep(30) # Wait before starting the next round
        except Exception as e:
            logging.error(f"A critical error occurred: {e}. Restarting participation loop after 30 seconds.")
            time.sleep(30)

if __name__ == "__main__":
    main()
