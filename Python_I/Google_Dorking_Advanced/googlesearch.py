# googlesearch.py
"""
GoogleSearch mejorada:
- Usa requests.Session
- Manejo de paginación robusto
- Retries y backoff
- Dedupe de resultados por link
- Parámetros extras: lr (language), safe, num por página (limitado por API)
- Manejo de errores HTTP con mensajes claros
"""

import requests
import time
from urllib.parse import quote_plus

class GoogleSearch:
    def __init__(self, api_key, engine_id, session=None, timeout=15, sleep_between=1.0):
        self.api_key = api_key
        self.engine_id = engine_id
        self.session = session or requests.Session()
        self.timeout = timeout
        self.sleep_between = sleep_between
        self.session.headers.update({
            "User-Agent": "ninja-dork-google/1.0"
        })

    def search(self, query, start_page=1, pages=1, lang="lang_es", safe="off", num=10, max_retries=3, backoff=1.0):
        """
        query: string
        start_page: página inicial (1-based)
        pages: número de páginas a traer
        lang: lr param p.ej 'lang_es'
        safe: 'off'|'active'
        num: resultados por página (max 10 por CSE)
        """
        final_results = []
        seen_links = set()
        results_per_page = max(1, min(10, int(num)))  # Google CSE limita a 10
        for page in range(pages):
            start_index = (start_page - 1) * results_per_page + 1 + (page * results_per_page)
            params = {
                "key": self.api_key,
                "cx": self.engine_id,
                "q": query,
                "start": start_index,
                "lr": lang,
                "safe": safe,
                "num": results_per_page
            }
            # Construir URL (más fácil debugging)
            url = "https://www.googleapis.com/customsearch/v1"
            attempt = 0
            while attempt < max_retries:
                try:
                    resp = self.session.get(url, params=params, timeout=self.timeout)
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("items", [])
                        processed = self.custom_results(items)
                        # Dedupe por link
                        for r in processed:
                            if r["link"] not in seen_links:
                                final_results.append(r)
                                seen_links.add(r["link"])
                        break
                    else:
                        # Mensaje y retry en caso de 429 o 5xx
                        if resp.status_code in (429, 500, 502, 503, 504):
                            attempt += 1
                            time.sleep(backoff * (2 ** (attempt - 1)))
                            continue
                        else:
                            raise Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")
                except requests.RequestException as e:
                    attempt += 1
                    time.sleep(backoff * (2 ** (attempt - 1)))
                    if attempt >= max_retries:
                        raise
            time.sleep(self.sleep_between)
        return final_results

    def custom_results(self, results):
        custom = []
        for r in results:
            custom.append({
                "title": r.get("title"),
                "description": r.get("snippet"),
                "link": r.get("link")
            })
        return custom
