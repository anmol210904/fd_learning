import requests
import json
import random
import base64
import time
import logging
import os
import torch
import torch.nn as nn

# --- Import your helper classes from separate files ---
# (Assuming they are in the same directory or accessible via PYTHONPATH)
# You will need to create these files based on your project's logic.
# For example:
# from digitalSignature import SignatureHandler
# from diffieHelman import KeyExchangeHandler
# from shamirClass import VectorShamirSecretSharing
# from model import MLModel

# --- Placeholder classes for demonstration if the files don't exist ---
# You can replace these with your actual implementations.
class SignatureHandler:
    def __init__(self):
        self.public_key_bytes = os.urandom(32)
    def sign_message(self, message):
        return os.urandom(64)

class KeyExchangeHandler:
    def __init__(self):
        self.public_key_bytes = os.urandom(32)
    def derive_shared_key(self, other_public_key):
        return os.urandom(32)

class VectorShamirSecretSharing:
    def __init__(self):
        self.PRIME = 65537 # A small prime for demonstration
    def split_secret(self, secret, num_shares, threshold):
        # This is a mock implementation. A real one is required.
        shares = []
        for i in range(1, num_shares + 1):
            shares.append((i, [s + i for s in secret]))
        return shares

class MLModel:
    def __init__(self, model_architecture):
        self.model = model_architecture
        # Optimizer and criterion are no longer needed as we are not training.

    def get_model_object(self):
        return self.model

    def run_epoch(self, data_loader):
        """
        This method now bypasses ML training and directly sets the model's weights
        to new random values to ensure different outputs on each run.
        The data_loader argument is ignored.
        """
        with torch.no_grad():
            for param in self.model.parameters():
                # Fill the tensor with new random numbers from a uniform distribution.
                param.data.uniform_(-0.1, 0.1)

    def put_weights(self, weights_list):
        with torch.no_grad():
            for param, new_weights in zip(self.model.parameters(), weights_list):
                param.copy_(new_weights)
# --- End of Placeholder classes ---


# --- Import the AESGCM class ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- CONFIGURATION ---
SERVER_URL = "http://127.0.0.1:5000"
VECTOR_SIZE = 61
PRECISION_FACTOR = 10**6
PUBLIC_VECTOR_A = [2] * VECTOR_SIZE

# --- CRYPTOGRAPHIC AND UTILITY CLASSES ---

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

class WeightHandler:
    def __init__(self, model_object, prime, precision_factor):
        self.model_object = model_object
        self.PRIME = prime
        self.PRECISION_FACTOR = precision_factor
        self.blueprint = self._create_blueprint()

    def _create_blueprint(self):
        blueprint = []
        if isinstance(self.model_object, nn.Module):
            for param in self.model_object.parameters():
                blueprint.append(param.shape)
        else:
            raise TypeError("Unsupported model type for blueprint.")
        return blueprint

    def flatten_weights(self):
        flat_weights = []
        if isinstance(self.model_object, torch.nn.Module):
            for param in self.model_object.parameters():
                flat_weights.extend(param.data.flatten().tolist())
        else:
            raise TypeError("Unsupported model type for flattening.")
        return flat_weights

    def deflatten_weights(self, flat_weights_array):
        structured_weights = []
        start_index = 0
        for shape in self.blueprint:
            num_elements = torch.prod(torch.tensor(shape)).item()
            param_slice = flat_weights_array[start_index : start_index + num_elements]
            structured_weights.append(torch.tensor(param_slice).view(shape))
            start_index += num_elements
        return structured_weights

    def encode_weights(self, flat_weights):
        """Encodes a list of floats into large integers for the crypto protocol."""
        return [int(w * self.PRECISION_FACTOR) % self.PRIME for w in flat_weights]

    def decode_weights(self, encoded_weights):
        """Decodes large integers from the server back into floats."""
        def _decode_value(value):
            """Converts a single value from the finite field back to a regular integer."""
            prime_half = self.PRIME // 2
            if value > prime_half:
                return value - self.PRIME
            return value

        decoded_integers = [_decode_value(w) for w in encoded_weights]
        return [w / self.PRECISION_FACTOR for w in decoded_integers]


# --- MAIN USER ORCHESTRATION CLASS ---

class User:
    def __init__(self, user_id, ml_model_handler, data_loader):
        self.user_id = user_id
        self.ml_model_handler = ml_model_handler
        self.data_loader = data_loader

        self.token = None
        self.signature_handler = SignatureHandler()
        self.dh_handler = KeyExchangeHandler()
        self.shamir_handler = VectorShamirSecretSharing()

        self.weight_handler = WeightHandler(
            self.ml_model_handler.get_model_object(),
            self.shamir_handler.PRIME,
            PRECISION_FACTOR
        )

        self.shared_keys = {}
        self.num_participants = 0

    def _make_request(self, method, endpoint, payload=None):
        url = f"{SERVER_URL}{endpoint}"
        logging.info(f"-> Calling API: {endpoint}")

        try:
            if method == 'POST':
                response = requests.post(url, json=payload, timeout=20)
            elif method == 'GET':
                response = requests.get(url, timeout=20)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logging.error(f"Error calling {endpoint}: {e.response.status_code} - {e.response.text}")
            raise
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error calling {endpoint}: {e}")
            raise

    def fetch_initial_model(self):
        data = self._make_request('GET', '/get_initial_model')
        global_model_encoded = data.get('global_model_weights', [])
        if not global_model_encoded:
            return

        decoded_floats = self.weight_handler.decode_weights(global_model_encoded)
        structured_weights = self.weight_handler.deflatten_weights(decoded_floats)
        self.ml_model_handler.put_weights(structured_weights)

    def register(self):
        signature = self.signature_handler.sign_message(self.dh_handler.public_key_bytes)
        payload = {
            "publicKey": base64.b64encode(self.dh_handler.public_key_bytes).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8'),
            "DSAPK": base64.b64encode(self.signature_handler.public_key_bytes).decode('utf-8')
        }
        response_data = self._make_request('POST', '/registerUser', payload)
        self.token = int(response_data['userToken'])

    def fetch_and_establish_keys(self):
        response_data = self._make_request('GET', f'/getUser/{self.token}')
        all_users_data = response_data['users']
        self.num_participants = len(all_users_data)

        for i, user_data in enumerate(all_users_data):
            other_user_token = i + 1
            if other_user_token == self.token: continue
            dh_pk_bytes = base64.b64decode(user_data['public_key'])
            shared_key = self.dh_handler.derive_shared_key(dh_pk_bytes)
            self.shared_keys[other_user_token] = AESCipher(shared_key)

    def run_local_training(self):
        # This now calls the modified run_epoch which sets random weights.
        self.ml_model_handler.run_epoch(self.data_loader)

    def prepare_and_submit_shares(self):
        flat_weights = self.weight_handler.flatten_weights()
        encoded_weights = self.weight_handler.encode_weights(flat_weights)

        mask = [random.randint(0, self.shamir_handler.PRIME - 1) for _ in range(len(flat_weights))]
        shares = self.shamir_handler.split_secret(mask, self.num_participants, self.num_participants)

        encrypted_shares = []
        for i in range(self.num_participants):
            recipient_token = i + 1
            share_json = json.dumps(shares[i][1]).encode('utf-8')
            if recipient_token == self.token:
                encrypted_shares.append(base64.b64encode(share_json).decode('utf-8'))
            else:
                encrypted_share = self.shared_keys[recipient_token].encrypt(share_json)
                encrypted_shares.append(base64.b64encode(encrypted_share).decode('utf-8'))

        payload = {"token": self.token, "shares": encrypted_shares}
        self._make_request('POST', '/submit_shamir_shares', payload)

        return encoded_weights, mask

    def receive_and_sum_shares(self):
        response_data = self._make_request('POST', '/get_shamir_shares', {"token": self.token})
        encrypted_shares = response_data['shares']

        decrypted_shares = []
        for i, enc_share_b64 in enumerate(encrypted_shares):
            sender_token = i + 1
            enc_bytes = base64.b64decode(enc_share_b64)
            if sender_token == self.token:
                decrypted_shares.append(json.loads(enc_bytes.decode('utf-8')))
            else:
                decrypted_json = self.shared_keys[sender_token].decrypt(enc_bytes)
                decrypted_shares.append(json.loads(decrypted_json.decode('utf-8')))

        summed_shares = [sum(col) % self.shamir_handler.PRIME for col in zip(*decrypted_shares)]
        return summed_shares

    def submit_final_data(self, encoded_weights, mask, summed_shares):
        masked_weights = [(w + m) % self.shamir_handler.PRIME for w, m in zip(encoded_weights, mask)]
        verification_tag = [(w * a + m) % self.shamir_handler.PRIME for w, m, a in zip(encoded_weights, mask, PUBLIC_VECTOR_A)]

        self._make_request('POST', '/submit_summed_shares', {"token": self.token, "summed_shares": summed_shares})
        self._make_request('POST', '/submit_data', {"token": self.token, "masked_weights": masked_weights, "verification_tags": verification_tag})

    def fetch_and_update_model(self):
        data = self._make_request('GET', '/get_global_model')

        global_model_encoded = data.get('global_model_weights', [])
        aggregated_tag_encoded = data.get('aggrigated_tag', [])

        if not global_model_encoded:
            return

        global_model_decoded = self.weight_handler.decode_weights(global_model_encoded)
        aggregated_tag_decoded = self.weight_handler.decode_weights(aggregated_tag_encoded)

        logging.info(f">> Final Received Weights: {[round(w, 4) for w in global_model_decoded]}")

        expected_tag = [(w * a) for w, a in zip(global_model_decoded, PUBLIC_VECTOR_A)]

        if all(abs(e - r) < 1e-9 for e, r in zip(expected_tag, aggregated_tag_decoded)):
            structured_weights = self.weight_handler.deflatten_weights(global_model_decoded)
            self.ml_model_handler.put_weights(structured_weights)
        else:
            logging.error("❌ MODEL VERIFICATION FAILED. NOT UPDATING WEIGHTS.")


def perform_action_with_retry(action_function):
    """
    Continuously tries to perform an action until it succeeds, with retries for specific errors.
    """
    while True:
        try:
            return action_function()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400 and ('Wrong Window' in e.response.text):
                time.sleep(10)
            else:
                raise
        except requests.exceptions.RequestException:
            time.sleep(10)

def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s', handlers=[logging.StreamHandler()])
    
    torch.manual_seed(int(time.time()))
    
    user_architecture = nn.Sequential(nn.Linear(10, 5), nn.ReLU(), nn.Linear(5, 1))
    ml_model = MLModel(user_architecture)
    
    # Initialize User with a placeholder for the data_loader, as it's no longer used.
    user = User(user_id=random.randint(100, 999), ml_model_handler=ml_model, data_loader=None)

    while True:
        try:
            logging.info("\n--- Starting New Round ---")

            perform_action_with_retry(user.fetch_initial_model)
            
            # This call now sets the model weights to new random values.
            user.run_local_training()

            local_weights = user.weight_handler.flatten_weights()
            logging.info(f"== My Local Weights: {[round(w, 4) for w in local_weights]}")
            
            perform_action_with_retry(user.register)
            perform_action_with_retry(user.fetch_and_establish_keys)
            
            encoded_weights, mask = perform_action_with_retry(user.prepare_and_submit_shares)
            summed_shares = perform_action_with_retry(user.receive_and_sum_shares)
            
            perform_action_with_retry(lambda: user.submit_final_data(encoded_weights, mask, summed_shares))
            perform_action_with_retry(user.fetch_and_update_model)

            logging.info("--- Round Complete, Waiting... ---")
            time.sleep(30)
            
        except Exception as e:
            logging.critical(f"A critical error occurred: {e}. Retrying in 30 seconds.")
            time.sleep(30)

if __name__ == "__main__":
    main()

