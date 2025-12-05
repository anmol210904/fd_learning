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
    def compute_aggregation_results(self, use_field_average: bool = False):
        """
        Performs the final aggregation.

        Behavior controlled by `use_field_average`:
        - If False (default): DO NOT divide — publish the summed values:
            self.global_model  := sum_of_true_weights (mod PRIME)
            self.aggregated_tag := sum_of_true_tags (mod PRIME)
            This is a straightforward, easy-to-inspect output for demos / visualization.

        - If True: perform an average step but *not* via modular inverse.
            Instead:
            1) Convert summed integers to signed integers.
            2) Convert to floats by dividing by PRECISION_FACTOR.
            3) Compute float average = (sum_floats / active_users).
            4) Re-encode average floats back to integers (signed -> modular rep).
            This yields server-side averaged values using ordinary float division,
            then maps them back into the finite field for downstream verification.

        Note: When using the float-division path you must ensure PRECISION_FACTOR is the same
        client <-> server and be aware of rounding. This path is mainly for demo/debug.
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
            # valid_summed_shares is a list of per-user summed-share vectors
            # Build tuples (id, share_vector) for reconstruct
            summed_shares_tuples = [(i + 1, share) for i, share in enumerate(valid_summed_shares)]
            reconstructed_summed_mask = shamir_handler.reconstruct_secret(summed_shares_tuples)

            # --- 2. Sum Masked Weights (mod prime) ---
            sum_of_masked_weights = [0] * vector_size
            for user_weights in valid_masked_weights:
                for i in range(vector_size):
                    sum_of_masked_weights[i] = (sum_of_masked_weights[i] + int(user_weights[i])) % prime

            # Remove summed mask to get sum of true encoded weights (mod prime)
            sum_of_true_weights = [
                (sum_of_masked_weights[i] - reconstructed_summed_mask[i] + prime) % prime
                for i in range(vector_size)
            ]

            # --- 3. Sum verification tags (mod prime) and remove mask contribution ---
            sum_of_verification_tags = [0] * vector_size
            for user_tags in valid_tags:
                for i in range(vector_size):
                    sum_of_verification_tags[i] = (sum_of_verification_tags[i] + int(user_tags[i])) % prime

            sum_of_true_tags = [
                (sum_of_verification_tags[i] - reconstructed_summed_mask[i] + prime) % prime
                for i in range(vector_size)
            ]

            # Store sums for inspection / client use
            # Default behaviour: publish sums (no division)
            if not use_field_average:
                # Publish summed values (mod prime). Clients must divide by active_users themselves
                # if they want an average in float-space.
                self.global_model = [val % prime for val in sum_of_true_weights]
                self.aggregated_tag = [val % prime for val in sum_of_true_tags]

                # Save active_users so get_global_model can optionally return it
                self._last_active_users = active_users

                print("Successfully computed summed global model and aggregated tag (no division).")
                return

            # -----------------------
            # FLOAT-AVERAGE-THEN-REENCODE PATH
            # -----------------------
            # This path converts the summed integers -> signed ints -> floats
            # computes a float average, then re-encodes back into modular integers.
            # WARNING: this is for demo/debug; it introduces floating rounding.
            try:
                # Helper: decode signed integer (centered around prime//2)
                def _decode_signed_int(x):
                    half = prime // 2
                    if x > half:
                        return x - prime
                    return x

                # 1) Convert summed true weights to signed integers, then to floats / PRECISION
                summed_signed_ints = [_decode_signed_int(int(v)) for v in sum_of_true_weights]
                summed_floats = [s / PRECISION_FACTOR for s in summed_signed_ints]

                # 2) Compute float-average
                averaged_floats = [s / float(active_users) for s in summed_floats]

                # 3) Re-encode averaged floats to integers: multiply by PRECISION and map to field rep
                reencoded_avgs = []
                for f in averaged_floats:
                    # round to nearest integer to reduce bias
                    rounded = int(round(f * PRECISION_FACTOR))
                    # map into field representative (mod prime)
                    if rounded < 0:
                        # convert negative to positive representative
                        rounded_mod = (rounded + prime) % prime
                    else:
                        rounded_mod = rounded % prime
                    reencoded_avgs.append(rounded_mod)

                # 4) Do same process for tags: note tags were sum(a*w + m). We can derive average tag
                # by decoding sum_of_true_tags similarly:
                summed_tag_signed = [_decode_signed_int(int(v)) for v in sum_of_true_tags]
                summed_tag_floats = [s / PRECISION_FACTOR for s in summed_tag_signed]
                averaged_tag_floats = [s / float(active_users) for s in summed_tag_floats]

                reencoded_tag_avgs = []
                for f in averaged_tag_floats:
                    rounded = int(round(f * PRECISION_FACTOR))
                    if rounded < 0:
                        rounded_mod = (rounded + prime) % prime
                    else:
                        rounded_mod = rounded % prime
                    reencoded_tag_avgs.append(rounded_mod)

                self.global_model = reencoded_avgs
                self.aggregated_tag = reencoded_tag_avgs
                self._last_active_users = active_users

                print("Successfully computed averaged global model (float-average path) and re-encoded tags.")
                return

            except Exception as e:
                print(f"Error during float-average re-encoding: {e}")
                # Fallback: publish summed values if re-encoding fails
                self.global_model = [val % prime for val in sum_of_true_weights]
                self.aggregated_tag = [val % prime for val in sum_of_true_tags]
                self._last_active_users = active_users
                print("Falling back to summed values (no division).")
                return

        except Exception as e:
            print(f"An error occurred during final aggregation: {e}")
            self.global_model, self.aggregated_tag = [], []
            return


    def get_global_model(self):
        return self.global_model
        
    def get_aggrigated_tag(self):
        return self.aggregated_tag

aggrigatorInstance = Agrigator()

