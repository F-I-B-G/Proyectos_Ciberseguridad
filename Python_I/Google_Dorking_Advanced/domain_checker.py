import argparse
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

# Desactiva warnings por certificados
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_url(url):
    try:
        response = requests.get(url, timeout=5, verify=False)
        if response.status_code == 200:
            print(f"[+] {url} está activo")
            return url
    except requests.RequestException:
        pass
    return None

def load_domains(file_path, wordlist_path=None):
    domains = []
    with open(file_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    # Si hay wordlist y '*' en los dominios, expandir
    if wordlist_path:
        with open(wordlist_path, "r") as w:
            words = [word.strip() for word in w if word.strip()]
        for line in lines:
            if "*" in line:
                for word in words:
                    domains.append(line.replace("*", word))
            else:
                domains.append(line)
    else:
        domains = lines

    return domains

def main():
    parser = argparse.ArgumentParser(description="Checker de URLs con soporte para patrones tipo *.dominio.com")
    parser.add_argument("input", help="Archivo con la lista de dominios o patrones")
    parser.add_argument("-w", "--wordlist", help="Archivo con posibles reemplazos para * (opcional)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Cantidad de hilos (default: 10)")
    args = parser.parse_args()

    domains = load_domains(args.input, args.wordlist)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.map(lambda d: check_url(f"http://{d}"), domains)
        executor.map(lambda d: check_url(f"https://{d}"), domains)

if __name__ == "__main__":
    main()
