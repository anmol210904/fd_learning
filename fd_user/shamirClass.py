import random
import functools

# A large prime number for the finite field. All calculations will be done modulo this prime.
# This ensures that the secret remains secure.
class VectorShamirSecretSharing:
    def __init__(self):
        # Define the prime as an instance attribute. This is the single source of truth.
        self.PRIME = 2**521 - 1

    def _evaluate_polynomial(self, coeffs, x):
        result = 0
        for coeff in reversed(coeffs):
            # Use self.PRIME
            result = (result * x + coeff) % self.PRIME
        return result

    def _extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        d, x1, y1 = self._extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return d, x, y

    def _mod_inverse(self, n):
        # Use self.PRIME
        d, x, y = self._extended_gcd(n, self.PRIME)
        if d != 1:
            raise Exception('Modular inverse does not exist')
        return x % self.PRIME

    def split_secret(self, secret_vector, num_shares, threshold):
        if threshold > num_shares:
            raise ValueError("Threshold cannot be greater than the number of shares.")
        shares = []
        for i in range(1, num_shares + 1):
            shares.append((i, []))
        for secret_element in secret_vector:
            # Use self.PRIME
            coeffs = [secret_element] + [random.randint(0, self.PRIME - 1) for _ in range(threshold - 1)]
            for i in range(1, num_shares + 1):
                share_value = self._evaluate_polynomial(coeffs, i)
                shares[i-1][1].append(share_value)
        return shares

    def reconstruct_secret(self, shares):
        if not shares:
            raise ValueError("Cannot reconstruct secret from an empty list of shares.")
        num_elements = len(shares[0][1])
        reconstructed_vector = []
        for i in range(num_elements):
            points = [(share_id, share_vector[i]) for share_id, share_vector in shares]
            secret_element = 0
            for j, (x_j, y_j) in enumerate(points):
                numerator = 1
                denominator = 1
                for m, (x_m, y_m) in enumerate(points):
                    if m != j:
                        # Use self.PRIME
                        numerator = (numerator * -x_m) % self.PRIME
                        denominator = (denominator * (x_j - x_m)) % self.PRIME
                lagrange_poly = (numerator * self._mod_inverse(denominator)) % self.PRIME
                term = (y_j * lagrange_poly) % self.PRIME
                secret_element = (secret_element + term) % self.PRIME
            reconstructed_vector.append(secret_element)
        return reconstructed_vector

