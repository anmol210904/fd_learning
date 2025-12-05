# config.py
SERVER_URL = "http://127.0.0.1:5000"

# Must match server VECTOR_SIZE for demo. Keep this in sync or derive dynamically later.
VECTOR_SIZE = 61

# Scaling factor used to convert floats -> large integers (and back)
PRECISION_FACTOR = 10**6

# Public vector 'a' used for verification tag; can be changed by user
PUBLIC_VECTOR_A = [2] * VECTOR_SIZE

# Estimated average time (seconds) local training takes — used to match server window timings.
TRAIN_TIME_ESTIMATE = 5.0

# HTTP settings
REQUEST_TIMEOUT = 20
RETRY_DELAY = 5
MAX_RETRIES = 5
