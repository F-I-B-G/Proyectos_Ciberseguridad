# file_downloader.py (versión extendida)
"""
FileDownloader:
- Descargas robustas (streaming, concurrencia)
- Soporte proxies (session.proxies)
- Integración simple con VirusTotal (opcional) para analizar URLs
- Función helper 'extract_links_from_url' para scrapear links de una página
"""

import os
import requests
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, unquote
from bs4 import BeautifulSoup

SAFE_FILENAME = re.compile(r'[^A-Za-z0-9._-]')

class FileDownloader:
    def __init__(self, directorio_destino="Descargas", max_workers=4, timeout=15, max_bytes=None, headers=None, verify_ssl=True, vt_api_key=None, session_proxies=None):
        self.directorio = directorio_destino
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.vt_api_key = vt_api_key  # si None, no chequea VT
        self.session = requests.Session()
        self.session.headers.update(headers or {"User-Agent": "Google-Dorking-Downloader/1.0"})
        self.session.verify = verify_ssl
        if session_proxies:
            self.session.proxies.update(session_proxies)
        os.makedirs(self.directorio, exist_ok=True)
        self._seen_filenames = set()

    def _sanitize_filename(self, name):
        name = unquote(name)
        name = os.path.basename(name)
        name = SAFE_FILENAME.sub("_", name)
        if not name:
            name = f"file_{int(time.time())}"
        base, ext = os.path.splitext(name)
        candidate = name
        i = 1
        while candidate in self._seen_filenames or os.path.exists(os.path.join(self.directorio, candidate)):
            candidate = f"{base}_{i}{ext}"
            i += 1
        self._seen_filenames.add(candidate)
        return candidate

    def _get_filename_from_url(self, url, response):
        cd = response.headers.get("content-disposition")
        if cd:
            m = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', cd, flags=re.I)
            if m:
                return self._sanitize_filename(m.group(1))
        parsed = urlparse(url)
        name = os.path.basename(parsed.path)
        if not name:
            name = parsed.netloc.replace(":", "_")
        return self._sanitize_filename(name)

    # --- Simple VirusTotal URL check using v2 endpoint (public API simple usage) ---
    def check_url_virustotal(self, url):
        """
        Devuelve:
            ('unknown'|'clean'|'malicious', details_dict)
        Usa la API v2 simple (report) para evitar flujos complejos.
        NOTA: Si no hay key devuelve ('not_configured', {})
        """
        if not self.vt_api_key:
            return 'not_configured', {}

        try:
            # v2 report endpoint (sencillo)
            params = {"apikey": self.vt_api_key, "resource": url}
            resp = requests.get("https://www.virustotal.com/vtapi/v2/url/report", params=params, timeout=15)
            if resp.status_code != 200:
                return 'error', {"status": resp.status_code, "text": resp.text[:200]}
            data = resp.json()
            # response_code: 0 = unknown, 1 = present
            if data.get("response_code") == 0:
                return 'unknown', data
            positives = data.get("positives", 0)
            total = data.get("total", 0)
            if positives and positives > 0:
                return 'malicious', {"positives": positives, "total": total, "scans": data.get("scans", {})}
            else:
                return 'clean', {"positives": positives, "total": total}
        except Exception as e:
            return 'error', {"error": str(e)}

    def descargar_archivo(self, url, max_retries=3, backoff_factor=1.0):
        """Descarga un único archivo y chequea VT si está configurado."""
        # Si VT configurado, chequeamos primero la URL
        if self.vt_api_key:
            vt_status, vt_details = self.check_url_virustotal(url)
            if vt_status == 'malicious':
                return False, f"VT flagged as malicious ({vt_details.get('positives')} hits)"
            elif vt_status == 'error':
                # no rompemos, solo avisamos
                print(f"[!] VT error checking {url}: {vt_details}")
            # if 'unknown' or 'clean' continue

        attempt = 0
        while attempt < max_retries:
            try:
                with self.session.get(url, stream=True, timeout=self.timeout, allow_redirects=True) as r:
                    r.raise_for_status()
                    cl = r.headers.get("Content-Length")
                    if cl and self.max_bytes and int(cl) > self.max_bytes:
                        return False, f"Skipped (Content-Length > max_bytes): {url}"
                    filename = self._get_filename_from_url(url, r)
                    ruta = os.path.join(self.directorio, filename)
                    total = 0
                    with open(ruta, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            if chunk:
                                total += len(chunk)
                                if self.max_bytes and total > self.max_bytes:
                                    f.close()
                                    os.remove(ruta)
                                    return False, f"Skipped (download exceeded max_bytes): {url}"
                                f.write(chunk)
                    return True, ruta
            except requests.RequestException as e:
                attempt += 1
                time.sleep(backoff_factor * (2 ** (attempt-1)))
                if attempt >= max_retries:
                    return False, f"Error after retries: {e}"
            except Exception as e:
                return False, f"Unexpected error: {e}"
        return False, "Max retries exceeded"

    def filtrar_descargar_archivos(self, urls, tipos_archivos=None, concurrency=None):
        """
        Filtra URLs por extensiones y descarga concurrentemente.
        tipos_archivos: None -> todos, otherwise list like ['pdf','sql']
        """
        # Normalizar y filtrar por ext si corresponde
        def keep(url):
            if not tipos_archivos:
                return True
            path = urlparse(url).path
            ext = os.path.splitext(path)[1].lstrip('.').lower()
            return ext in [t.lower() for t in tipos_archivos]

        to_download = [u for u in urls if keep(u)]
        to_download = list(dict.fromkeys(to_download))  # dedupe manteniendo orden

        workers = concurrency or self.max_workers
        results = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_to_url = {ex.submit(self.descargar_archivo, url): url for url in to_download}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    ok, info = future.result()
                    results.append((url, ok, info))
                    if ok:
                        print(f"[+] Descargado: {info}")
                    else:
                        print(f"[-] {info} -> {url}")
                except Exception as e:
                    results.append((url, False, str(e)))
                    print(f"[X] Exception downloading {url}: {e}")
        return results

# -------------------
# Helper: scraping
# -------------------
def extract_links_from_url(url, session=None, timeout=15):
    """
    Extrae enlaces absolutos de una URL (href) y devuelve lista de URLs encontradas.
    Usa BeautifulSoup. Devuelve solo http(s) links.
    """
    s = session or requests.Session()
    try:
        r = s.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            # normalizar a absoluto
            full = urljoin(r.url, href)
            if full.startswith("http://") or full.startswith("https://"):
                links.add(full)
        return list(links)
    except Exception as e:
        raise
