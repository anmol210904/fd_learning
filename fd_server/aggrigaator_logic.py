import threading
import time
import random
from flask import Flask, request, jsonify

# --- Import your helper classes ---
# (Assuming they are in the same directory or accessible via PYTHONPATH)
from shamirClass import VectorShamirSecretSharing
from globalVariables import global_values
from classes import UserPKs
import digitalSignature
import base64

# --- CONFIGURATION ---
VECTOR_SIZE = 61
PRECISION_FACTOR = 10**6

# --- INITIALIZE HANDLERS ---
shamir_handler = VectorShamirSecretSharing()

class Agrigator:
    def __init__(self):
        self.users = []
        self.mask_shares_matrix = []
        self.masked_weights = []
        self.verification_tags = []
        self.summed_shares = []
        self.global_model = []
        self.aggregated_tag = []

        # --- Initialize with a random starter model ---
        print("--- SERVER INIT: Generating initial random global model ---")
        initial_random_weights = [random.uniform(-0.1, 0.1) for _ in range(VECTOR_SIZE)]
        self.global_model = [int(w * PRECISION_FACTOR) % shamir_handler.PRIME for w in initial_random_weights]
        print(f"--- SERVER INIT: Initial model created. ---")

    def mainfunction(self):
        while True:
            global_values.window = 0
            time.sleep(30)

            # --- REGISTRATION WINDOW ---
            global_values.window = 1
            print(f"\n--- SERVER LOOP: Window {global_values.window} (REGISTRATION) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (REGISTRATION) is CLOSED. ---")

            n = len(self.users)
            if n < 2: # Need at least 2 users for the protocol to be meaningful
                print(f"Not enough users registered ({n}). Restarting round.")
                self.users = [] # Reset for next round
                time.sleep(10)
                continue

            # Initialize data structures for the round
            self.masked_weights = [[] for _ in range(n)]
            self.verification_tags = [[] for _ in range(n)]
            self.summed_shares = [[] for _ in range(n)]
            self.mask_shares_matrix = [["" for _ in range(n)] for _ in range(n)]
            self.global_model = []
            self.aggregated_tag = []
            print(f"Server data structures initialized for {n} users.")

            # --- KEY DISTRIBUTION WINDOW ---
            global_values.window = 2
            print(f"--- SERVER LOOP: Window {global_values.window} (KEY DISTRIBUTION) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (KEY DISTRIBUTION) is CLOSED. ---")

            # --- SUBMIT SHAMIR SHARES WINDOW ---
            global_values.window = 3
            print(f"--- SERVER LOOP: Window {global_values.window} (SUBMIT SHARES) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (SUBMIT SHARES) is CLOSED. ---")

            # --- GET SHAMIR SHARES WINDOW ---
            global_values.window = 4
            print(f"--- SERVER LOOP: Window {global_values.window} (GET SHARES) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (GET SHARES) is CLOSED. ---")

            # --- SUBMIT FINAL DATA WINDOW ---
            global_values.window = 5
            print(f"--- SERVER LOOP: Window {global_values.window} (SUBMIT DATA) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (SUBMIT DATA) is CLOSED. ---")

            # --- AGGREGATION AND MODEL READY WINDOW ---
            self.compute_aggregation_results()
            global_values.window = 6
            print(f"--- SERVER LOOP: Window {global_values.window} (GET MODEL) is OPEN for 20 seconds. ---")
            time.sleep(20)
            print(f"--- SERVER LOOP: Window {global_values.window} (GET MODEL) is CLOSED. ---")

            # --- RESET FOR NEXT ROUND ---
            self.users = []
            print("\n=============== ROUND COMPLETE ===============")


    def registerUser(self, PK, SignedPK, DSAPK):
        # In a real app, you would verify that the user is not already registered
        self.users.append(UserPKs(PK, SignedPK, DSAPK))
        return len(self.users)

    def getUsersPk(self):
        return self.users

    def populateMaskSharesMatrix(self, shares, token):
        row_index = token - 1
        if 0 <= row_index < len(self.mask_shares_matrix):
            self.mask_shares_matrix[row_index] = shares

    def get_shmair_shares_for_user(self, token):
        column_index = token - 1
        if 0 <= column_index < len(self.mask_shares_matrix[0]):
            return [row[column_index] for row in self.mask_shares_matrix]
        return []
        
    def receive_masked_weights(self, masked_weights, token):
        user_index = token - 1
        if 0 <= user_index < len(self.masked_weights):
            self.masked_weights[user_index] = masked_weights
            
    def receive_verification_tag(self, tag_array, token):
        user_index = token - 1
        if 0 <= user_index < len(self.verification_tags):
            self.verification_tags[user_index] = tag_array
            
    def receive_summed_shares(self, summed_shares, token):
        user_index = token - 1
        if 0 <= user_index < len(self.summed_shares):
            self.summed_shares[user_index] = summed_shares

    # --- CORRECTED AGGREGATION LOGIC ---
    def compute_aggregation_results(self):
        """
        Performs the final aggregation using correct finite field arithmetic.
        """
        try:
            num_users = len(self.users)
            if num_users < 2:
                print("Aggregation skipped: Not enough users.")
                self.global_model, self.aggregated_tag = [], []
                return

            # Filter out empty submissions to handle dropouts
            valid_masked_weights = [w for w in self.masked_weights if w]
            valid_tags = [t for t in self.verification_tags if t]
            valid_summed_shares = [s for s in self.summed_shares if s]

            # The number of users who actually submitted data
            active_users = len(valid_masked_weights)

            if active_users < 2:
                print(f"Aggregation failed: Only {active_users} user(s) submitted data.")
                self.global_model, self.aggregated_tag = [], []
                return
            
            vector_size = len(valid_masked_weights[0])
            prime = shamir_handler.PRIME

            # --- 1. Reconstruct the Sum of All Masks ---
            summed_shares_tuples = [(i + 1, share) for i, share in enumerate(valid_summed_shares)]
            reconstructed_summed_mask = shamir_handler.reconstruct_secret(summed_shares_tuples)

            # --- 2. Process Masked Weights ---
            sum_of_masked_weights = [0] * vector_size
            for user_weights in valid_masked_weights:
                for i in range(vector_size):
                    sum_of_masked_weights[i] = (sum_of_masked_weights[i] + user_weights[i]) % prime
            
            sum_of_true_weights = [(sum_of_masked_weights[i] - reconstructed_summed_mask[i] + prime) % prime for i in range(vector_size)]
            
            # Use modular inverse for division
            mod_inverse_n = shamir_handler._mod_inverse(active_users)
            self.global_model = [(val * mod_inverse_n) % prime for val in sum_of_true_weights]

            # --- 3. Process Verification Tags (Parallel Logic) ---
            sum_of_verification_tags = [0] * vector_size
            for user_tags in valid_tags:
                for i in range(vector_size):
                    sum_of_verification_tags[i] = (sum_of_verification_tags[i] + user_tags[i]) % prime

            sum_of_true_tags = [(sum_of_verification_tags[i] - reconstructed_summed_mask[i] + prime) % prime for i in range(vector_size)]
            self.aggregated_tag = [(val * mod_inverse_n) % prime for val in sum_of_true_tags]

            print("Successfully computed global model and aggregated tag.")

        except Exception as e:
            print(f"An error occurred during final aggregation: {e}")
            self.global_model, self.aggregated_tag = [], []

    def get_global_model(self):
        return self.global_model
        
    def get_aggrigated_tag(self):
        return self.aggregated_tag

aggrigatorInstance = Agrigator()

