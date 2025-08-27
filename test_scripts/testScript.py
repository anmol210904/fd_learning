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
NUM_USERS = 4
PRECISION_FACTOR = 10**6 # For encoding floats to integers

# --- CRYPTOGRAPHIC AND UTILITY CLASSES (Self-contained for this example) ---

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
        return nonce + ciphertext # Prepend nonce for decryption
    def decrypt(self, ciphertext_with_nonce):
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]
        aead = AESGCM(self.key)
        return aead.decrypt(nonce, ciphertext, None)

class VectorShamirSecretSharing:
    PRIME = 2**521 - 1 # Use a smaller prime for faster demonstration
    def __init__(self):
        # Define the prime as an instance attribute. This is the single source of truth.
        self.PRIME = 2**521 - 1
    def _evaluate_polynomial(self, coeffs, x):
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % self.PRIME
        return result
    def _mod_inverse(self, n):
        return pow(n, -1, self.PRIME)
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
        self.shared_keys = {} # {other_user_token: aes_key}

    def register(self):
        logging.info(f"--- User {self.user_id}: Registering with server ---")
        signature = self.signature_handler.sign_message(self.dh_handler.public_key_bytes)
        payload = {
            "publicKey": base64.b64encode(self.dh_handler.public_key_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "DSAPK": base64.b64encode(self.signature_handler.public_key_bytes).decode('utf-8')
        }
        
        url = f"{SERVER_URL}/registerUser"
        logging.info(f"User {self.user_id}: Making POST request to {url}")
        logging.info(f"User {self.user_id}: REQUEST PAYLOAD:\n{json.dumps(payload, indent=2)}")

        response = requests.post(url, json=payload)
        
        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()
        
        response_data = response.json()
        self.token = int(response_data['userToken'])
        logging.info(f"User {self.user_id}: Registration successful. Received token: {self.token}")

    def fetch_and_establish_keys(self):
        logging.info(f"--- User {self.user_id}: Fetching public keys of other users ---")
        
        url = f"{SERVER_URL}/getUser/{self.token}"
        logging.info(f"User {self.user_id}: Making GET request to {url}")

        response = requests.get(url)

        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()
        
        response_data = response.json()
        all_users_data = response_data['users']
        
        for i, user_data in enumerate(all_users_data):
            other_user_token = i + 1
            if other_user_token == self.token:
                continue # Don't establish a key with yourself

            dh_pk_bytes = base64.b64decode(user_data['public_key'])
            shared_key = self.dh_handler.derive_shared_key(dh_pk_bytes)
            self.shared_keys[other_user_token] = AESCipher(shared_key)
            logging.info(f"User {self.user_id}: Established shared AES key with user {other_user_token}")

    def submit_mask_shares(self):
        logging.info(f"--- User {self.user_id}: Generating and submitting mask shares ---")
        mask = [random.randint(0, 100) for _ in range(VECTOR_SIZE)]
        logging.info(f"User {self.user_id}: Generated original mask: {mask}")
        
        shares = self.shamir_handler.split_secret(mask, NUM_USERS, NUM_USERS)
        logging.info(f"User {self.user_id}: Split mask into shares (before encryption):\n{json.dumps(shares, indent=2)}")

        encrypted_shares_payload = []
        for i in range(NUM_USERS):
            recipient_token = i + 1
            share_vector_json = json.dumps(shares[i]).encode('utf-8')
            if recipient_token == self.token:
                # Share for self is not encrypted
                encrypted_shares_payload.append(base64.b64encode(share_vector_json).decode('utf-8'))
            else:
                encrypted_share = self.shared_keys[recipient_token].encrypt(share_vector_json)
                encrypted_shares_payload.append(base64.b64encode(encrypted_share).decode('utf-8'))
        
        payload = {"token": self.token, "shares": encrypted_shares_payload}
        url = f"{SERVER_URL}/submit_shamir_shares"
        logging.info(f"User {self.user_id}: Making POST request to {url}")
        logging.info(f"User {self.user_id}: REQUEST PAYLOAD:\n{json.dumps(payload, indent=2)}")
        
        response = requests.post(url, json=payload)

        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()

        logging.info(f"User {self.user_id}: Submitted encrypted shares successfully.")
        return mask # Return the original mask to be used later

    def receive_and_decrypt_shares(self):
        logging.info(f"--- User {self.user_id}: Fetching and decrypting my shares ---")
        payload = {"token": self.token}
        
        url = f"{SERVER_URL}/get_shamir_shares"
        logging.info(f"User {self.user_id}: Making POST request to {url}")
        logging.info(f"User {self.user_id}: REQUEST PAYLOAD:\n{json.dumps(payload, indent=2)}")

        response = requests.post(url, json=payload)

        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()
        
        response_data = response.json()
        received_encrypted_shares = response_data['shares']
        decrypted_shares = []
        for i, enc_share_b64 in enumerate(received_encrypted_shares):
            sender_token = i + 1
            enc_share_bytes = base64.b64decode(enc_share_b64)
            if sender_token == self.token:
                decrypted_shares.append(json.loads(enc_share_bytes.decode('utf-8')))
            else:
                decrypted_share_json = self.shared_keys[sender_token].decrypt(enc_share_bytes)
                decrypted_shares.append(json.loads(decrypted_share_json.decode('utf-8')))
        
        logging.info(f"User {self.user_id}: Successfully decrypted all received shares:\n{json.dumps(decrypted_shares, indent=2)}")
        return decrypted_shares

    def submit_summed_shares(self, decrypted_shares):
        logging.info(f"--- User {self.user_id}: Summing decrypted shares and submitting to server ---")
        summed_shares = [0] * VECTOR_SIZE
        for share_vector in decrypted_shares:
            for i in range(VECTOR_SIZE):
                summed_shares[i] = (summed_shares[i] + share_vector[i]) % self.shamir_handler.PRIME
        
        logging.info(f"User {self.user_id}: Calculated summed shares (b_sum,{self.user_id}): {summed_shares}")

        payload = {"token": self.token, "summed_shares": summed_shares}
        url = f"{SERVER_URL}/submit_summed_shares"
        logging.info(f"User {self.user_id}: Making POST request to {url}")
        logging.info(f"User {self.user_id}: REQUEST PAYLOAD:\n{json.dumps(payload, indent=2)}")

        response = requests.post(url, json=payload)

        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()

        logging.info(f"User {self.user_id}: Submitted summed shares successfully.")

    def submit_masked_weights_and_tag(self, mask):
        logging.info(f"--- User {self.user_id}: Masking weights and submitting final data ---")
        weights = [random.uniform(0.0, 1.0) for _ in range(VECTOR_SIZE)]
        logging.info(f"User {self.user_id}: Generated original weights: {[round(w, 4) for w in weights]}")

        # Encode floats to integers
        encoded_weights = [int(w * PRECISION_FACTOR) for w in weights]
        logging.info(f"User {self.user_id}: Encoded weights (multiplied by {PRECISION_FACTOR}): {encoded_weights}")
        logging.info(f"User {self.user_id}: Using mask from previous step: {mask}")
        
        masked_weights = [(w + m) for w, m in zip(encoded_weights, mask)]
        logging.info(f"User {self.user_id}: Calculated masked weights: {masked_weights}")

        # This is a simplified verification tag for demonstration
        verification_tag = [(w * 2 + m) for w, m in zip(encoded_weights, mask)]
        logging.info(f"User {self.user_id}: Calculated verification tags: {verification_tag}")
        
        payload = {
            "token": self.token,
            "masked_weights": masked_weights,
            "verification_tags": verification_tag
        }
        url = f"{SERVER_URL}/submit_data"
        logging.info(f"User {self.user_id}: Making POST request to {url}")
        logging.info(f"User {self.user_id}: REQUEST PAYLOAD:\n{json.dumps(payload, indent=2)}")
        
        response = requests.post(url, json=payload)
        
        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()
        
        logging.info(f"User {self.user_id}: Submitted final data successfully.")

    def submit_all_final_data(self, decrypted_shares, mask):
        """Combines the submission of summed shares and the final masked data."""
        self.submit_summed_shares(decrypted_shares)
        self.submit_masked_weights_and_tag(mask)

    def fetch_global_model(self):
        logging.info(f"--- User {self.user_id}: Fetching global model ---")
        
        url = f"{SERVER_URL}/get_global_model"
        logging.info(f"User {self.user_id}: Making GET request to {url}")

        response = requests.get(url)

        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()

        response_data = response.json()
        global_model_encoded = response_data['global_model_weights']
        
        if not global_model_encoded:
            logging.warning(f"User {self.user_id}: Global model is empty, something went wrong on the server.")
            return

        # Decode integers back to floats
        global_model_decoded = [w / PRECISION_FACTOR for w in global_model_encoded]
        
        logging.info(f"User {self.user_id}: Final decoded global model: {[round(w, 2) for w in global_model_decoded]}")

def main():
    """Orchestrates the entire simulation for all users, phase by phase."""
    
    # --- Set up logging to file and console ---
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("simulation.log", mode='w'), # Overwrite log file each run
            logging.StreamHandler()
        ]
    )

    users = [User(user_id=i+1) for i in range(NUM_USERS)]
    
    # --- PHASE 1: REGISTRATION ---
    input("Press Enter to start PHASE 1: REGISTRATION...")
    logging.info("\n\n=============== PHASE 1: REGISTRATION ===============\n")
    for user in users:
        user.register()
    
    # --- PHASE 2: KEY EXCHANGE ---
    input("\nPress Enter to start PHASE 2: KEY EXCHANGE...")
    logging.info("\n\n=============== PHASE 2: KEY EXCHANGE ===============\n")
    for user in users:
        user.fetch_and_establish_keys()
        
    # --- PHASE 3: SUBMIT MASK SHARES ---
    input("\nPress Enter to start PHASE 3: SUBMIT MASK SHARES...")
    logging.info("\n\n=============== PHASE 3: SUBMIT MASK SHARES ===============\n")
    user_masks = {} # Store the original masks to use them later
    for user in users:
        mask = user.submit_mask_shares()
        user_masks[user.token] = mask
        
    # --- PHASE 4: RECEIVE MASK SHARES ---
    input("\nPress Enter to start PHASE 4: RECEIVE MASK SHARES...")
    logging.info("\n\n=============== PHASE 4: RECEIVE MASK SHARES ===============\n")
    user_decrypted_shares = {}
    for user in users:
        decrypted_shares = user.receive_and_decrypt_shares()
        user_decrypted_shares[user.token] = decrypted_shares

    # --- PHASE 5: SUBMIT ALL DATA (SUMMED SHARES, MASKED WEIGHTS, TAGS) ---
    input("\nPress Enter to start PHASE 5: SUBMIT ALL DATA...")
    logging.info("\n\n=============== PHASE 5: SUBMIT ALL DATA ===============\n")
    for user in users:
        user.submit_all_final_data(user_decrypted_shares[user.token], user_masks[user.token])

    # --- PHASE 6: FETCH GLOBAL MODEL ---
    input("\nPress Enter to start PHASE 6: FETCH GLOBAL MODEL...")
    logging.info("\n\n=============== PHASE 6: FETCH GLOBAL MODEL ===============\n")
    for user in users:
        user.fetch_global_model()

if __name__ == "__main__":
    main()