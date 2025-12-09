# utils/http_client.py
import requests
import time
from typing import Optional

def safe_get(url: str, headers: dict = None, retries: int = 3, timeout: int = 10, backoff: float = 1.0) -> Optional[requests.Response]:
    """Realiza GET con retries y timeout. Devuelve Response o None."""
    headers = headers or {}
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            # Considerar 429 o 5xx como reintentables
            if resp.status_code in (429, ) or 500 <= resp.status_code < 600:
                raise requests.RequestException(f"Status {resp.status_code}")
            return resp
        except requests.RequestException:
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
            else:
                return None
