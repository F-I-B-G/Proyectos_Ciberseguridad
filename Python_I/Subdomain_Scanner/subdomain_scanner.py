import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import sys

class SubdomainScanner:
    def __init__(self, domain, wordlist, resolver_list=None, ipv6=False, threads=10):
        self.domain = domain
        self.wordlist = self.load_file(wordlist)
        self.resolver_list = self.setup_resolver(resolver_list)
        self.ipv6 = ipv6
        self.threads = threads
        self.record_type = 'AAAA' if ipv6 else 'A' # A => ipv4 y AAAA => ipv6
    
    def load_file(self, wordlist):
        try:
            with open(wordlist, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError as e:
            print(f'[!] {e}')
            sys.exit(1)
    
    def setup_resolver(self, resolver_list):
        resolver = dns.resolver.Resolver() # Para encontrar su dirección ipv4 o ipv6 asociada
        resolver.timeout = 1
        resolver.lifetime = 1
        if resolver_list:
            try:
                with open(resolver_list, 'r') as file:
                    # Se irán recorriendo cada servidor DNS
                    resolver.nameservers = file.read().splitlines()
            except FileNotFoundError:
                print('[!] Error al leer el fichero con los servidores DNS.')
                sys.exit(1)
        return resolver
    
    def scan(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(self.scan_domain, self.wordlist))
        self.present_results(results)
    
    def scan_domain(self, subdomain):
        # Compone el dominio completo
        full_domain = f'{subdomain}.{self.domain}'
        try:
            answers = self.resolver_list.resolve(full_domain, self.record_type)
            return (full_domain, [answer.address for answer in answers])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return None
    
    def present_results(self, results):
        if not results or all(result is None for result in results):
            print('[!] No se han encontrados subdominios activos.')
        else:
            print('[*] Resultados del escaneo de subdominios: ')
            for result in results:
                if result:
                    domain, addresses = result
                    print(f'[*] Subdomio: {domain}')
                    for address in addresses:
                        print(f'    - IP: {address}')

if __name__ == '__main__':
    scanner = SubdomainScanner(
        domain='example.com',
        wordlist='subdomains.txt',
        resolver_list='nameservers.txt',
        ipv6=False,
        threads=10     
    )
    scanner.scan()

# Los descubrimientos de subdominios se harán consuktando a los servers DNS para evitar tener que interacturar con el objetivo. 
# Es menos efectivo en algunos casos pero no genera ruido.