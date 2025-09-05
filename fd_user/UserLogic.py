from digitalSignature import SignatureHandler
from diffieHelman import KeyExchangeHandler
from shamirClass import VectorShamirSecretSharing
from AESCipher import AESCipher
import requests
import base64
import logging
import json
import random

SERVER_URL = "http://127.0.0.1:5000" # <-- IMPORTANT: CHANGE THIS TO YOUR SERVER'S PUBLIC IP
VECTOR_SIZE = 10
PRECISION_FACTOR = 10**6
# A public vector known to all clients and the server for verification
PUBLIC_VECTOR_A = [2] * VECTOR_SIZE 


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
        logging.info(f"--- User {self.user_id}: Registering with server ---")
        signature = self.signature_handler.sign_message(self.dh_handler.public_key_bytes)
        payload = {
            "publicKey": base64.b64encode(self.dh_handler.public_key_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "DSAPK": base64.b64encode(self.signature_handler.public_key_bytes).decode('utf-8')
        }
        response = requests.post(f"{SERVER_URL}/registerUser", json=payload)
        response.raise_for_status()
        self.token = int(response.json()['userToken'])
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
        verification_tag = [(w * a + m) for w, m, a in zip(encoded_weights, mask, PUBLIC_VECTOR_A)]
        payload_data = {"token": self.token, "masked_weights": masked_weights, "verification_tags": verification_tag}
        requests.post(f"{SERVER_URL}/submit_data", json=payload_data).raise_for_status()
        logging.info(f"User {self.user_id}: Submitted masked weights and tag successfully.")

    def fetch_and_verify_global_model(self):
        logging.info(f"--- User {self.user_id}: Fetching and verifying global model ---")
        url = f"{SERVER_URL}/get_global_model"
        response = requests.get(url)
        logging.info(f"User {self.user_id}: RESPONSE | Status: {response.status_code} | Body:\n{response.text}")
        response.raise_for_status()

        response_data = response.json()
        global_model_encoded = response_data.get('global_model_weights', [])
        aggregated_tag_encoded = response_data.get('aggrigated_tag', [])

        if not global_model_encoded:
            logging.warning(f"User {self.user_id}: Global model is empty.")
            return

        # Decode integers back to floats for both model and tag
        global_model_decoded = [w / PRECISION_FACTOR for w in global_model_encoded]
        aggregated_tag_decoded = [t / PRECISION_FACTOR for t in aggregated_tag_encoded]
        
        logging.info(f"User {self.user_id}: Final decoded global model: {[round(w, 4) for w in global_model_decoded]}")

        # Perform the final verification check
        expected_tag = [(w * a) for w, a in zip(global_model_decoded, PUBLIC_VECTOR_A)]
        
        # Use a tolerance for floating point comparison
        if all(abs(e - r) < 1e-9 for e, r in zip(expected_tag, aggregated_tag_decoded)):
            logging.info("✅ VERIFICATION SUCCESSFUL: The aggregated tag matches the global model.")
        else:
            logging.error("❌ VERIFICATION FAILED: The server's aggregated tag does not match the global model.")
            logging.error(f"   Expected Tag: {[round(t, 4) for t in expected_tag]}")
            logging.error(f"   Received Tag: {[round(t, 4) for t in aggregated_tag_decoded]}")