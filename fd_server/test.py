import requests
import deffieHelman
import digitalSignature
import base64
import shamirClass
import random
# import os
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# class AESCipher:
#     """
#     A class for AES encryption and decryption using GCM mode.

#     AES-GCM is an authenticated encryption with associated data (AEAD) mode.
#     It provides both confidentiality and integrity, meaning the data is not
#     only kept secret but also protected from tampering.
#     """

#     def __init__(self, key: bytes):
#         """
#         Initializes the cipher with a 32-byte key for AES-256.

#         Args:
#             key (bytes): A 32-byte (256-bit) key. It's crucial that this key
#                          is kept secret and is generated using a
#                          cryptographically secure random number generator.
        
#         Raises:
#             ValueError: If the key is not 32 bytes long.
#         """
#         if len(key) != 32:
#             raise ValueError("Key must be 32 bytes long for AES-256.")
#         self.key = key
#         self.aesgcm = AESGCM(self.key)

#     def encrypt(self, plaintext: bytes, associated_data: bytes = None) -> bytes:
#         """
#         Encrypts the given plaintext.

#         Args:
#             plaintext (bytes): The data to encrypt.
#             associated_data (bytes, optional): Additional, unencrypted data
#                                                that will be authenticated but not
#                                                encrypted. Defaults to None.

#         Returns:
#             bytes: A byte string containing the nonce prepended to the ciphertext.
#                    The nonce is essential for decryption.
#         """
#         # A nonce (number used once) must be unique for each encryption with the same key.
#         # 12 bytes (96 bits) is a standard size for GCM nonces.
#         nonce = os.urandom(12)
        
#         ciphertext = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        
#         # Prepend the nonce to the ciphertext; it's needed for decryption.
#         return nonce + ciphertext

#     def decrypt(self, ciphertext_with_nonce: bytes, associated_data: bytes = None) -> bytes:
#         """
#         Decrypts the given ciphertext.

#         This method will automatically verify the integrity of the data.
#         If the ciphertext or associated data has been tampered with, it will
#         raise an InvalidTag exception.

#         Args:
#             ciphertext_with_nonce (bytes): The encrypted data, with the nonce
#                                            prepended.
#             associated_data (bytes, optional): The same associated data provided
#                                                during encryption. Defaults to None.

#         Returns:
#             bytes: The original plaintext.
        
#         Raises:
#             cryptography.exceptions.InvalidTag: If authentication fails.
#         """
#         # Extract the nonce from the first 12 bytes.
#         nonce = ciphertext_with_nonce[:12]
#         ciphertext = ciphertext_with_nonce[12:]
        
#         # Decrypt and verify the data.
#         return self.aesgcm.decrypt(nonce, ciphertext, associated_data)




# def get_request(endpoint: str, port: int = 5000):
#     """Send a GET request to localhost:<port>/<endpoint> and return the response."""
#     url = f"http://127.0.0.1:{port}/{endpoint.lstrip('/')}"
#     try:
#         response = requests.get(url)
#         return response.json() if response.headers.get("Content-Type") == "application/json" else response.text
#     except Exception as e:
#         return {"error": str(e)}

# def post_request(endpoint: str, data: dict, port: int = 5000):
#     """Send a POST request with JSON data to localhost:<port>/<endpoint> and return the response."""
#     url = f"http://127.0.0.1:{port}/{endpoint.lstrip('/')}"
#     try:
#         response = requests.post(url, json=data)
#         return response.json() if response.headers.get("Content-Type") == "application/json" else response.text
#     except Exception as e:
#         return {"error": str(e)}
    

# user1diffie = deffieHelman.KeyExchangeHandler()
# user2diffie = deffieHelman.KeyExchangeHandler()
# user3diffie = deffieHelman.KeyExchangeHandler()
# user1DSA = digitalSignature.SignatureHandler()
# user2DSA = digitalSignature.SignatureHandler()
# user3DSA = digitalSignature.SignatureHandler()

# user1Dict = {
#     'publicKey': base64.b64encode(user1diffie.public_key_bytes).decode('utf-8'),
#     'signature': base64.b64encode(user1DSA.sign_message(user1diffie.public_key_bytes)).decode('utf-8'),
#     'DSAPK': base64.b64encode(user1DSA.public_key_bytes).decode('utf-8')
# }
# print(post_request('/registerUser', user1Dict))

# user2Dict = {
#     'publicKey': base64.b64encode(user2diffie.public_key_bytes).decode('utf-8'),
#     'signature': base64.b64encode(user2DSA.sign_message(user2diffie.public_key_bytes)).decode('utf-8'),
#     'DSAPK': base64.b64encode(user2DSA.public_key_bytes).decode('utf-8')
# }
# print(post_request('/registerUser', user2Dict))

# user3Dict = {
#     'publicKey': base64.b64encode(user3diffie.public_key_bytes).decode('utf-8'),
#     'signature': base64.b64encode(user3DSA.sign_message(user3diffie.public_key_bytes)).decode('utf-8'),
#     'DSAPK': base64.b64encode(user3DSA.public_key_bytes).decode('utf-8')
# }
# print(post_request('/registerUser', user3Dict))


# input("Get to window 2? ")
# #successfully registered 3 users
# #now to get the users 
# users1Fetchedlist = get_request('/getUser/1')
# users2Fetchedlist = get_request('/getUser/2')
# users3Fetchedlist = get_request('/getUser/3')
# print(users1Fetchedlist)



# input("start to window 3?")
# user1Weights = [3,4,5]
# user2Weights = [4,5,6]
# user3Weights = [7,8,9]
# user1Mask = [4,5,6]
# user2Mask=[12,21,53]
# user3Mask = [34,1,431]

# user1AES = [user1diffie.derive_shared_key(user1diffie.public_key_bytes),user1diffie.derive_shared_key(user2diffie.public_key_bytes),user1diffie.derive_shared_key(user2diffie.public_key_bytes)]
# user2AES = [user2diffie.derive_shared_key(user1diffie.public_key_bytes),user2diffie.derive_shared_key(user2diffie.public_key_bytes),user2diffie.derive_shared_key(user2diffie.public_key_bytes)]
# user3AES = [user1diffie.derive_shared_key(user3diffie.public_key_bytes),user3diffie.derive_shared_key(user2diffie.public_key_bytes),user3diffie.derive_shared_key(user2diffie.public_key_bytes)]

# shamir =  shamirClass.VectorShamirSecretSharing()

# user1MaskShares = shamir.split_secret(user1Mask,3,3)
# user2MaskShares = shamir.split_secret(user2Mask,3,3)
# user3MaskShares = shamir.split_secret(user3Mask,3,3)

# user1MaskEncrypedShares=[]
# user2MaskEncrypedShares=[]
# user3MaskEncrypedShares=[]

# aes = AESCipher()
# #for user1 
# for i in range(3):
#     user1MaskShares.append(base64.b64encode(aes.encrypt(user1MaskShares[i], user1AES[i])).decode('utf-8'))

# for i in range(3):
#     user2MaskShares.append(base64.b64encode(aes.encrypt(user2MaskShares[i], user2AES[i])).decode('utf-8'))

# for i in range(3):
#     user3MaskShares.append(base64.b64encode(aes.encrypt(user3MaskShares[i], user3AES[i])).decode('utf-8'))



# # we will send this to the server
# print(user1MaskEncrypedShares)
# print(user2MaskEncrypedShares)
# print(user3MaskEncrypedShares)


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
        shares = [[] for _ in range(num_shares)]
        for secret_element in secret_vector:
            coeffs = [secret_element] + [random.randint(0, self.PRIME - 1) for _ in range(threshold - 1)]
            for i in range(1, num_shares + 1):
                share_value = self._evaluate_polynomial(coeffs, i)
                shares[i-1].append(share_value)
        return shares


    def reconstruct_secret(self, shares):
        if not shares:
            raise ValueError("Cannot reconstruct secret from an empty list of shares.")
        num_elements = len(shares[0])
        reconstructed_vector = []
        for i in range(num_elements):
            points = [(idx + 1, share[i]) for idx, share in enumerate(shares)]
            secret_element = 0
            for j, (x_j, y_j) in enumerate(points):
                numerator = 1
                denominator = 1
                for m, (x_m, _) in enumerate(points):
                    if m != j:
                        numerator = (numerator * -x_m) % self.PRIME
                        denominator = (denominator * (x_j - x_m)) % self.PRIME
                lagrange_poly = (numerator * self._mod_inverse(denominator)) % self.PRIME
                term = (y_j * lagrange_poly) % self.PRIME
                secret_element = (secret_element + term) % self.PRIME
            reconstructed_vector.append(secret_element)
        return reconstructed_vector



class VectorShamirSecretSharing1:
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
    

l3 = [
    351547481757887222264306829173675949907980329296671036450668130003652326137720662874918699217949528350946708919186393420300844743575205990783456856741050080,
    2646461360581424206674021632421826061761916522915823036229021778549302949008300874901692630890879433219912978050464310904635126919633305619011540548926431927,
    4729198604240541105129445361299410295428531960391060800136649628351181009099222309583336520011237377097451229010512279367090603976526652000640083894745866055
  ]

l2 = [
    6061961483506707309339584861038433893846954929593248842217016321833176614918578867740964561630774356073241411321671864768246947715688433346300801039295890831,
    5205211438449292852711611127524664713314786252607129433734042074996767029578597944227960245135888440957785132735621160294184904821350902669934157977334654016,
    5566638857005061494984376381431920409219213168410635066845597559451044187404793937252393124402986139342216253272046275184910851960455263822191771397135073049
  ]

l1 = [
    1368247216167005091930215385259613099031337953065488223803817972374930383940901278700951901450488143304728300754289161603398674134685602140990296559638836081,
    6611323538299021355480904183077853765150625845016290224789189301875513774375049669968249248392746814876912910515960009338347191848045348734454987224730862479,
    1701973435548011221613927661304985904986557414899179663668559863605469456572501150017094404178755495317300406471381896050173321301707498551120400668514765388
  ]

prime = 2**521 - 1

l4 = [l1,l2,l3]

shamir = VectorShamirSecretSharing()


mis = [[1368247216167005091930215385259613099031337953065488223803817972374930383940901278700951901450488143304728300754289161603398674134685602140990296559638836081, 6611323538299021355480904183077853765150625845016290224789189301875513774375049669968249248392746814876912910515960009338347191848045348734454987224730862479, 1701973435548011221613927661304985904986557414899179663668559863605469456572501150017094404178755495317300406471381896050173321301707498551120400668514765388], [6061961483506707309339584861038433893846954929593248842217016321833176614918578867740964561630774356073241411321671864768246947715688433346300801039295890831, 5205211438449292852711611127524664713314786252607129433734042074996767029578597944227960245135888440957785132735621160294184904821350902669934157977334654016, 5566638857005061494984376381431920409219213168410635066845597559451044187404793937252393124402986139342216253272046275184910851960455263822191771397135073049], [351547481757887222264306829173675949907980329296671036450668130003652326137720662874918699217949528350946708919186393420300844743575205990783456856741050080, 2646461360581424206674021632421826061761916522915823036229021778549302949008300874901692630890879433219912978050464310904635126919633305619011540548926431927, 4729198604240541105129445361299410295428531960391060800136649628351181009099222309583336520011237377097451229010512279367090603976526652000640083894745866055]]
print(mis == l4)
print(shamir.reconstruct_secret(l4))



#[84, 98, 47] [48, 3, 83] [0, 64, 93]


#masked weights [[505461, 107357, 533211], [340113, 863806, 147147], [954835, 863822, 168460]]

#orignal weights = [505377, 107259, 533164] , [340065, 863803, 147064],  [954835, 863758, 168367]


