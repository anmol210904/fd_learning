# run_client.py
"""
Entry point for the user client.

Terminal prints ONLY:
  1) decoded local weights to be summed (first 20 floats),
  2) decoded global weights received from server (first 20 floats),
  3) verification result (SUCCESS / FAILED).

Full debug & payloads are written to client_verbose.log.
"""

import logging
import time
from typing import Callable

from config import TRAIN_TIME_ESTIMATE, PRECISION_FACTOR
from vector_model import VectorModel
from apiclient import APIClient
from client_core import ClientCore

# --------------------------
# Logging: file = verbose; console = minimal
# --------------------------
LOG_FILENAME = "client_verbose.log"

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)  # capture everything to file

# File handler: DEBUG -> client_verbose.log
file_handler = logging.FileHandler(LOG_FILENAME, mode="w", encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(file_formatter)

# Reset root handlers to ensure only file handler captures DEBUG
if root_logger.handlers:
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)
root_logger.addHandler(file_handler)

# Keep console quiet; we'll use print() to show exactly 3 things.
console_logger = logging.getLogger("console")
console_logger.setLevel(logging.WARNING)

logger = logging.getLogger("run_client")


# --------------------------
# Helper retry wrapper
# --------------------------
def perform_action_with_retry(action_fn: Callable, name: str, retry_delay: int = 10):
    """
    Calls action_fn. Retries on transient errors until success.
    """
    while True:
        try:
            return action_fn()
        except Exception as e:
            msg = str(e)
            # transient conditions: "Wrong Window", timeouts, connection errors
            if "Wrong Window" in msg or "timed out" in msg or "Connection" in msg or "failed after" in msg:
                logger.warning("%s: transient issue - %s. Retrying in %ds", name, msg, retry_delay)
                time.sleep(retry_delay)
                continue
            logger.exception("%s: fatal error", name)
            raise


# --------------------------
# Orchestration
# --------------------------
def run_round_once():
    model = VectorModel()
    api = APIClient()
    core = ClientCore(model, api)

    # 1. fetch initial model (window 0) - optional
    try:
        _ = perform_action_with_retry(core.fetch_initial_model, "Fetch Initial Model")
    except Exception as e:
        logger.warning("Initial model fetch skipped/failed: %s", e)

    # 2. local training (simulated)
    logger.info("Starting local training (simulated)")
    elapsed = model.run_epoch(simulate=True)
    logger.info("Local training simulated in %.2fs (TRAIN_TIME_ESTIMATE=%s)", elapsed, TRAIN_TIME_ESTIMATE)

    # short countdown for server readiness
    countdown = 5
    logger.info("Pre-aggregation warning: will begin aggregation sequence in %d seconds.", countdown)
    for i in range(countdown, 0, -1):
        logger.info("Aggregation starts in %d...", i)
        time.sleep(1)

    # 3. register & key exchange
    perform_action_with_retry(core.register, "Registration")
    perform_action_with_retry(core.fetch_users_and_establish_keys, "Key Exchange")

    # 4. prepare & submit shamir shares (window 3)
    encoded_weights, mask = perform_action_with_retry(core.prepare_and_send_shares, "Prepare & Submit Shares")

    # ====== Terminal Output #1: decoded weights to be summed (first 20 floats) ======
    # Proper signed decoding before dividing by PRECISION_FACTOR
    prime = core.shamir.PRIME
    half = prime // 2

    def _decode_signed(v: int) -> int:
        vm = int(v) % prime
        return vm - prime if vm > half else vm

    decoded_local = [_decode_signed(w) / PRECISION_FACTOR for w in encoded_weights][:20]
    print("WEIGHTS_TO_SUM (first 20 decoded floats):")
    print([round(x, 6) for x in decoded_local])
    # =========================================================================

    # 5. receive shares and sum (window 4)
    summed_shares = perform_action_with_retry(core.receive_and_sum_shares, "Receive & Sum Shares")

    # 6. submit masked weights & verification tags (window 5)
    perform_action_with_retry(lambda: core.submit_final_data(encoded_weights, mask, summed_shares), "Submit Final Data")

    # 7. fetch global model and update (window 6)
    success, global_ints = perform_action_with_retry(core.fetch_and_update_global, "Fetch & Update Global Model")

    # ====== Terminal Output #2: decoded global floats (first 20) ======
    if global_ints is not None:
        decoded_global = [_decode_signed(v) / PRECISION_FACTOR for v in global_ints][:20]
    else:
        decoded_global = []

    print("SUMMED_WEIGHTS_RECEIVED (first 20 decoded floats):")
    print([round(x, 6) for x in decoded_global])
    # =========================================================================

    # ====== Terminal Output #3: verification result ======
    if success:
        print("VERIFICATION RESULT: VERIFICATION SUCCESS")
    else:
        print("VERIFICATION RESULT: VERIFICATION FAILED")
    # =========================================================================

    logger.info("Round complete.")


if __name__ == "__main__":
    run_round_once()
