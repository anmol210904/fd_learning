from globalVariables import global_values
import digitalSignature
import deffieHelman
import time
import random
from classes import UserPKs
from shamirClass import shamir_handler
import threading



class Agrigator:

    def __init__(self):
        self.users = []
        self.mask_shares_matrix = []
        self.masked_weights = []
        self.verification_tags = []
        self.summed_shares = [] # To store b_sum,i from each user
        self.global_model = [] # To store the final result

        # 2. INITIALIZE THE LOCK
        # This creates a lock specific to this instance of the Agrigator.
        self._lock = threading.Lock()


    def mainfunction(self):
        while(True):
                    

            # --- After registration, initialize data structures ---

            #LETS START WITH WINDOW 0 SO THAT BLA BLA 
            #window 0 is absence of all windows 
            global_values.window = 0
            time.sleep(30)


            #lets start with the registration round
            global_values.window = 1
            print("Window 1 started")
            time.sleep(30)


            #not lets make the window 1 end
            print("window  1 ends")
            global_values.window =  0

            n = len(self.users)
            print("The value of n is ",n)
            self.masked_weights = [[] for _ in range(n)]
            self.verification_tags = [[] for _ in range(n)]
            self.summed_shares = [[] for _ in range(n)]
            self.mask_shares_matrix = [["" for _ in range(n)] for _ in range(n)]


            #lets start window2
            print("Window 2 started")
            global_values.window =  2
            time.sleep(30)


            #lets start window 3
            #submittion of shmir shares starts
            print("Lets start window 3")
            global_values.window =  3
            time.sleep(30)

            #lets starts window 4
            #fetching of shamir shares start
            print("weindow = 4")
            global_values.window =  4
            time.sleep(30)



            # lets start window 5
            #submittion of masked model and tags start
            global_values.window =  5
            print("window = 5")
            time.sleep(30)



            global_values.window = 0
            print("window 0 starts to let the model calculate")
            self.compute_and_average_weights()
            print("window 6 starts get your weights back")
            global_values.window =  6
            print(self.get_global_model())
           

            input("Should we start the next round?")

            


    # ... (Your existing functions: registerUser, getUsersPk, etc.) ...
    def registerUser(self, PK, SignedPK, DSAPK):
        """
        Safely registers a user and returns a unique token (their position).
        This method is now thread-safe.
        """
        # 3. ACQUIRE THE LOCK BEFORE THE CRITICAL SECTION
        with self._lock:
            # --- Critical Section Start ---
            # Only one thread can execute this code at a time.
            self.users.append(UserPKs(PK, SignedPK, DSAPK))
            token = len(self.users)
            # --- Critical Section End ---
            
        return str(token)

    def getUsersPk(self):
        return self.users

    def populateMaskSharesMatrix(self, shares, token):
       
        try:
            n = len(self.mask_shares_matrix)
            if not (1 <= token <= n): return
            row_index = token - 1
            self.mask_shares_matrix[row_index] = shares
            
        except Exception as e:
            print(f"An unexpected error occurred in populateMaskSharesMatrix: {e}")

    def get_shmair_shares_for_user(self, token):

       
        try:
            n = len(self.mask_shares_matrix)
            if not (1 <= token <= n): return []
            column_index = token - 1
            return [row[column_index] for row in self.mask_shares_matrix]
        except Exception as e:
            print(f"An unexpected error occurred in get_shmair_shares_for_user: {e}")
            return []

    def receive_masked_weights(self, masked_weights, token):
        try:
            n = len(self.users)
            if not (1 <= token <= n): return
            user_index = token - 1
            self.masked_weights[user_index] = masked_weights
        except Exception as e:
            print(f"An unexpected error occurred in receive_masked_weights: {e}")

    def receive_verification_tag(self, tag_array, token):
        try:
            n = len(self.users)
            if not (1 <= token <= n): return
            user_index = token - 1
            self.verification_tags[user_index] = tag_array
        except Exception as e:
            print(f"An unexpected error occurred in receive_verification_tag: {e}")
            
    def receive_summed_shares(self, summed_shares, token):
        """Receives and stores the summed shares (b_sum,i) from a user."""
        try:
            n = len(self.users)
            if not (1 <= token <= n): return
            user_index = token - 1
            self.summed_shares[user_index] = summed_shares
        except Exception as e:
            print(f"An unexpected error occurred in receive_summed_shares: {e}")


    # --- NEW FUNCTIONS ---
    # In your Agrigator class in aggregator.py

    # def compute_and_average_weights(self):

    #     print(self.masked_weights)
    #     print("*****************************************")
    #     print(self.summed_shares)
    #     """Performs final aggregation using correct finite field arithmetic."""
    #     try:
    #         num_users = len(self.users)
    #         if num_users == 0 or not self.masked_weights or not self.masked_weights[0]:
    #             print("Aggregation skipped: Not enough data.")
    #             self.global_model = []
    #             return

    #         vector_size = len(self.masked_weights[0])
    #         sum_of_masked_weights = [0] * vector_size

    #         for user_weights in self.masked_weights:
    #             if user_weights:
    #                 for i in range(vector_size):
    #                     sum_of_masked_weights[i] = (sum_of_masked_weights[i] + user_weights[i]) % shamir_handler.PRIME

    #         shares_for_reconstruction = []
    #         for i, shares in enumerate(self.summed_shares):
    #             if shares:
    #                 shares_for_reconstruction.append((i + 1, shares))
            
    #         if len(shares_for_reconstruction) < num_users:
    #             print("Not enough summed shares to reconstruct.")
    #             self.global_model = []
    #             return

    #         sum_of_masks = shamir_handler.reconstruct_secret(shares_for_reconstruction)

    #         sum_of_true_weights = [0] * vector_size
    #         for i in range(vector_size):
    #             sum_of_true_weights[i] = (sum_of_masked_weights[i] - sum_of_masks[i] + shamir_handler.PRIME) % shamir_handler.PRIME
            
    #         mod_inverse_n = shamir_handler._mod_inverse(num_users)
    #         self.global_model = [(val * mod_inverse_n) % shamir_handler.PRIME for val in sum_of_true_weights]
            
    #         print("Successfully computed the new global model (in finite field).")

    #     except Exception as e:
    #         print(f"An error occurred during final aggregation: {e}")
    #         self.global_model = []


    def compute_and_average_weights(self):
        """
        Performs final aggregation with robust error handling.
        It sums the masked weights, reconstructs the summed mask, unmasks the weights,
        and averages the result.
        """
        try:
            # --- 1. Pre-computation Checks (Guard Clauses) ---
            num_users = len(self.users)
            if num_users == 0:
                self.global_model = []
                return

            if not self.masked_weights or not self.summed_shares:
                self.global_model = []
                return

            # --- 2. Reconstruct the Sum of All Masks ---
            summed_shares_tuples = [(i, share) for i, share in enumerate(self.summed_shares, 1)]
            reconstructed_summed_mask = shamir_handler.reconstruct_secret(summed_shares_tuples)

            # --- 3. Sum the Masked Weights Column-wise ---
            summed_masked_weights_1d = [sum(column) for column in zip(*self.masked_weights)]

            # --- 4. Unmask and Average the Weights ---
            # Ensure the global model is empty before populating
            self.global_model = []
            
            # Use a list comprehension for a clean implementation
            unmasked_weights = [
                i - j for i, j in zip(summed_masked_weights_1d, reconstructed_summed_mask)
            ]

            # Average the result by dividing by the number of users
            self.global_model = [weight / num_users for weight in unmasked_weights]

        except Exception as e:
            # --- 5. Catch-All Error Handling ---
            # In a real application, you might log the error 'e' here
            # Reset the global model to ensure a clean state
            self.global_model = []


            
    def get_global_model(self):
        """
        Returns the computed global model for the current round.
        """
        return self.global_model


aggrigatorInstance = Agrigator()