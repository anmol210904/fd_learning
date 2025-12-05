# apiclient.py
"""
HTTP wrapper for server endpoints.
This version logs full payloads/responses at DEBUG to the verbose file,
but does not print endpoint hits to the terminal (no INFO console prints).
"""

import time
import requests
from typing import Any, Dict, List
from config import SERVER_URL, REQUEST_TIMEOUT, RETRY_DELAY, MAX_RETRIES

import logging
logger = logging.getLogger("apiclient")

class APIClient:
    def __init__(self, base_url: str = None):
        self.base = base_url or SERVER_URL

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        # Debug to verbose log only
        logger.debug("POST %s - payload: %s", path, payload)

        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
                # If server signals wrong window, wait and retry
                if r.status_code == 400 and "Wrong Window" in r.text:
                    logger.debug("%s returned Wrong Window (attempt %d). Retrying after %ds", path, attempt + 1, RETRY_DELAY)
                    time.sleep(RETRY_DELAY)
                    continue
                r.raise_for_status()
                # log full response body to file
                try:
                    resp_json = r.json()
                    logger.debug("Response for %s: %s", path, resp_json)
                    return resp_json
                except ValueError:
                    # non-JSON response
                    logger.debug("Non-JSON response for %s: %s", path, r.text)
                    return {"raw": r.text}
            except requests.exceptions.RequestException as e:
                last_exc = e
                try:
                    txt = getattr(e.response, "text", "") if hasattr(e, "response") else ""
                    if txt and "Wrong Window" in txt:
                        logger.debug("%s Wrong Window message via exception; retrying.", path)
                        time.sleep(RETRY_DELAY)
                        continue
                except Exception:
                    pass
                logger.debug("Network/HTTP error on %s: %s. Retry %d/%d", path, e, attempt + 1, MAX_RETRIES)
                time.sleep(RETRY_DELAY)
        logger.error("POST %s failed after %d attempts: last error: %s", path, MAX_RETRIES, last_exc)
        raise last_exc or Exception(f"POST {path} failed after {MAX_RETRIES} attempts")

    def _get(self, path: str) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        logger.debug("GET %s", path)

        last_exc = None
        for attempt in range(MAX_RETRIES):
            try:
                r = requests.get(url, timeout=REQUEST_TIMEOUT)
                if r.status_code == 400 and "Wrong Window" in r.text:
                    logger.debug("%s returned Wrong Window (attempt %d). Retrying after %ds", path, attempt + 1, RETRY_DELAY)
                    time.sleep(RETRY_DELAY)
                    continue
                r.raise_for_status()
                try:
                    resp_json = r.json()
                    logger.debug("Response for %s: %s", path, resp_json)
                    return resp_json
                except ValueError:
                    logger.debug("Non-JSON response for %s: %s", path, r.text)
                    return {"raw": r.text}
            except requests.exceptions.RequestException as e:
                last_exc = e
                try:
                    txt = getattr(e.response, "text", "") if hasattr(e, "response") else ""
                    if txt and "Wrong Window" in txt:
                        logger.debug("%s Wrong Window message via exception; retrying.", path)
                        time.sleep(RETRY_DELAY)
                        continue
                except Exception:
                    pass
                logger.debug("Network/HTTP error on %s: %s. Retry %d/%d", path, e, attempt + 1, MAX_RETRIES)
                time.sleep(RETRY_DELAY)
        logger.error("GET %s failed after %d attempts: last error: %s", path, MAX_RETRIES, last_exc)
        raise last_exc or Exception(f"GET {path} failed after {MAX_RETRIES} attempts")

    # High-level endpoints
    def register_user(self, public_key_b64: str, signature_b64: str, dsapk_b64: str) -> int:
        payload = {"publicKey": public_key_b64, "signature": signature_b64, "DSAPK": dsapk_b64}
        resp = self._post("/registerUser", payload)
        return int(resp["userToken"])

    def get_users(self, token: int) -> List[Dict]:
        resp = self._get(f"/getUser/{token}")
        return resp.get("users", [])

    def submit_shamir_shares(self, token: int, shares_b64_list: List[str]) -> Dict:
        payload = {"token": token, "shares": shares_b64_list}
        return self._post("/submit_shamir_shares", payload)

    def get_shamir_shares(self, token: int) -> Dict:
        payload = {"token": token}
        return self._post("/get_shamir_shares", payload)

    def submit_data(self, token: int, masked_weights: List[int], verification_tags: List[int]) -> Dict:
        payload = {"token": token, "masked_weights": masked_weights, "verification_tags": verification_tags}
        return self._post("/submit_data", payload)

    def submit_summed_shares(self, token: int, summed_shares: List[int]) -> Dict:
        payload = {"token": token, "summed_shares": summed_shares}
        return self._post("/submit_summed_shares", payload)

    def get_global_model(self) -> Dict:
        return self._get("/get_global_model")

    def get_initial_model(self) -> Dict:
        return self._get("/get_initial_model")
