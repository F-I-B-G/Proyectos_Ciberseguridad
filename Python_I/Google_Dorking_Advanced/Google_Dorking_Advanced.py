#!/usr/bin/env python3
"""
Google_Dorking_Advanced.py
Herramienta avanzada para dorking + scraping + descargas + VirusTotal.

----------------------------------------------------------
OPCIONES (LECTURA RÁPIDA)
----------------------------------------------------------
-q / --query           → Dork único a ejecutar.
--dorks-file           → Archivo .txt con lista de dorks (uno por línea).
--dork-template        → Dork plantilla que contenga {palabra} como marcador.
--wordlist             → Archivo .txt con palabras para reemplazar {palabra} en la plantilla.
--start-page / --pages → Rango de páginas a obtener.
--json / --html / --csv→ Exportar resultados en distintos formatos.
--txt                  → Exportar resultados en texto plano (URL por línea).
--download             → Descargar archivos filtrando por extensión o 'all'.
--scrape               → Scrapear páginas para extraer links embebidos.
--use-vt               → Analizar URLs con VirusTotal antes de descargar.
----------------------------------------------------------

Ejemplos:
1. Dork único:
   python Google_Dorking_Advanced.py -q "filetype:sql 'password'" --pages 2

2. Lista de dorks desde archivo:
   python Google_Dorking_Advanced.py --dorks-file mydorks.txt --pages 3

3. Plantilla + wordlist:
   python Google_Dorking_Advanced.py --dork-template "site:{palabra}.com inurl:admin" --wordlist subdominios.txt

4. Descargar solo PDFs:
   python Google_Dorking_Advanced.py -q "filetype:pdf site:example.com" --download pdf
"""

import os
import sys
import argparse
from dotenv import load_dotenv
from googlesearch import GoogleSearch
from results_parser import ResultsProcessor
from file_downloader import FileDownloader, extract_links_from_url
from pathlib import Path
from datetime import datetime

# Cargar .env
load_dotenv()
GOOGLE_API_KEY = os.getenv("API_KEY_GOOGLE")
SEARCH_ENGINE_ID = os.getenv("SEARCH_ENGINE_ID")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def env_config():
    """Pide claves y las guarda en .env"""
    from dotenv import set_key
    Path(".env").touch(exist_ok=True)
    api_key = input("Introduce tu API KEY de Google: ").strip()
    engine_id = input("Introduce el ID del buscador personalizado de Google: ").strip()
    vt_key = input("Introduce tu VIRUSTOTAL API KEY (opcional): ").strip()
    set_key(".env", "API_KEY_GOOGLE", api_key)
    set_key(".env", "SEARCH_ENGINE_ID", engine_id)
    if vt_key:
        set_key(".env", "VIRUSTOTAL_API_KEY", vt_key)
    print("[+] .env actualizado. Reejecutá el script.")

def read_lines_file(path):
    """Lee archivo de texto y devuelve lista limpia."""
    if not path: return []
    p = Path(path)
    if not p.exists():
        print(f"[X] No existe {path}")
        return []
    items = []
    for line in p.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        items.append(line)
    return items

def main():
    parser = argparse.ArgumentParser(description="Google Dorking Advanced - dorks + scraping + downloads + VT")
    parser.add_argument("-q", "--query", type=str, help="Dork/consulta única")
    parser.add_argument("--dorks-file", type=str, help="Archivo .txt con dorks (uno por línea)")
    parser.add_argument("--dork-template", type=str, help="Plantilla de dork con marcador {palabra}")
    parser.add_argument("--wordlist", type=str, help="Archivo .txt con palabras para reemplazar en la plantilla")
    parser.add_argument("--configure", action="store_true", help="Configura .env (API keys)")
    parser.add_argument("--start-page", type=int, default=1)
    parser.add_argument("--pages", type=int, default=1)
    parser.add_argument("--lang", type=str, default="lang_es")
    parser.add_argument("--safe", type=str, default="off", choices=["off","active"])
    parser.add_argument("--num", type=int, default=10, help="Resultados por página (1-10)")
    parser.add_argument("--json", type=str, help="Exportar JSON")
    parser.add_argument("--html", type=str, help="Exportar HTML")
    parser.add_argument("--csv", type=str, help="Exportar CSV")
    parser.add_argument("--txt", type=str, help="Exportar TXT (solo URLs)")
    parser.add_argument("--download", type=str, help="Extensiones a descargar o 'all'")
    parser.add_argument("--download-dir", type=str, default="Descargas", help="Carpeta destino")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--max-size", type=int, default=None)
    parser.add_argument("--proxies", type=str, default=None)
    parser.add_argument("--scrape", action="store_true")
    parser.add_argument("--use-vt", action="store_true")
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--sleep", type=float, default=1.0)
    args = parser.parse_args()

    if args.configure:
        env_config()
        sys.exit(0)

    if not GOOGLE_API_KEY or not SEARCH_ENGINE_ID:
        print("[X] Faltan API_KEY_GOOGLE o SEARCH_ENGINE_ID en .env. Ejecutá --configure.")
        sys.exit(1)

    queries = []

    # Dork único
    if args.query:
        queries.append(args.query)

    # Archivo de dorks
    if args.dorks_file:
        queries.extend(read_lines_file(args.dorks_file))

    # Plantilla + wordlist
    if args.dork_template and args.wordlist:
        words = read_lines_file(args.wordlist)
        for w in words:
            queries.append(args.dork_template.replace("{palabra}", w))

    if not queries:
        print("[X] No se indicó query, dorks-file ni plantilla+wordlist.")
        sys.exit(1)

    # Config proxies
    session_proxies = None
    if args.proxies:
        if Path(args.proxies).exists():
            lines = [l.strip() for l in Path(args.proxies).read_text().splitlines() if l.strip()]
            proxy = lines[0] if lines else None
            if proxy:
                session_proxies = {"http": proxy, "https": proxy}
        else:
            proxy = args.proxies
            session_proxies = {"http": proxy, "https": proxy}

    gsearch = GoogleSearch(GOOGLE_API_KEY, SEARCH_ENGINE_ID, timeout=args.timeout, sleep_between=args.sleep)
    if session_proxies:
        gsearch.session.proxies.update(session_proxies)

    all_results = []
    for q in queries:
        print(f"\n[+] Ejecutando dork: {q}")
        try:
            res = gsearch.search(query=q, start_page=args.start_page, pages=args.pages, lang=args.lang, safe=args.safe, num=args.num)
            print(f"[+] {len(res)} resultados obtenidos.")
            for r in res:
                r['_dork'] = q
            all_results.extend(res)
        except Exception as e:
            print(f"[X] Error en '{q}': {e}")

    rp = ResultsProcessor(all_results, metadata={"generated_at": datetime.utcnow().isoformat()+"Z", "total_results": len(all_results)})
    rp.mostrar_pantalla()

    # Exportaciones
    if args.json:
        rp.exportar_json(args.json)
    if args.html:
        rp.exportar_html(args.html)
    if args.csv:
        rp.exportar_csv(args.csv)
    if args.txt:
        Path(args.txt).write_text("\n".join([r['link'] for r in rp.resultados if r.get('link')]), encoding='utf-8')
        print(f"[+] Exportado TXT: {args.txt}")

    # Descargas
    urls = [r['link'] for r in rp.resultados if r.get('link')]
    extra_links = []
    if args.scrape:
        for url in urls:
            try:
                extra_links.extend(extract_links_from_url(url, session=gsearch.session, timeout=args.timeout))
            except Exception as e:
                print(f"  [-] Error scrappeando {url}: {e}")
        urls.extend(extra_links)

    download_types = None
    if args.download and args.download.lower() != "all":
        download_types = [t.strip().lstrip('.') for t in args.download.split(',') if t.strip()]

    if args.download or args.scrape:
        fd = FileDownloader(
            directorio_destino=args.download_dir,
            max_workers=args.concurrency,
            timeout=args.timeout,
            max_bytes=args.max_size,
            headers=None,
            verify_ssl=True,
            vt_api_key=(VIRUSTOTAL_KEY if args.use_vt else None),
            session_proxies=session_proxies
        )
        results_download = fd.filtrar_descargar_archivos(urls, tipos_archivos=download_types, concurrency=args.concurrency)
        print(f"\n[+] Descargas exitosas: {len([r for r in results_download if r[1]])}")
        print(f"[-] Fallidas/omitidas: {len([r for r in results_download if not r[1]])}")

if __name__ == "__main__":
    main()
