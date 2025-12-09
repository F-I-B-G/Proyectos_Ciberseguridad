"""
Herramienta de Enumeración DNS - Uso rápido:

[1] Enumerar TODOS los registros DNS
    - Consulta todos los registros comunes y algunos avanzados (A, AAAA, MX, TXT, etc.).
    - Útil para obtener la máxima información posible de un dominio.

[2] Elegir tipos de registros específicos
    - Permite consultar solo los tipos que te interesan.
    - Ideal cuando buscás datos puntuales (ej: solo MX o TXT).

[3] Resolución inversa (PTR lookup)
    - Ingresa una IP y devuelve el dominio asociado si existe.
    - Útil para fingerprinting y reconocimiento pasivo.

Al final de cada enumeración se puede exportar el resultado a:
    - .txt  → salida simple legible
    - .json → formato estructurado para análisis posterior
    - .html → visualizable en navegador con formato
"""

import dns.resolver
import dns.reversename
import json
import os
from datetime import datetime


class DNSEnumerator:
    def __init__(self):
        # Tipos de registros DNS de interés
        self.record_types = [
            'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT',
            'PTR', 'SRV', 'CAA', 'NAPTR', 'DNSKEY'
        ]
        self.resolver = dns.resolver.Resolver()
        self.results = {}  # Guarda resultados para exportar

    def resolve_domain(self, target, record_type):
        """Realiza una consulta DNS para un tipo de registro específico."""
        try:
            respuesta = self.resolver.resolve(target, record_type)
            return [str(r) for r in respuesta]
        except dns.resolver.NoAnswer:
            return [f"No hay respuesta para {record_type}"]
        except dns.resolver.NXDOMAIN:
            return [f"El dominio {target} no existe."]
        except dns.exception.Timeout:
            return [f"Tiempo de espera agotado para {record_type}"]
        except Exception as e:
            return [f"Error al consultar {record_type}: {e}"]

    def reverse_lookup(self, ip):
        """Realiza una consulta PTR (resolución inversa) para una IP."""
        try:
            rev_name = dns.reversename.from_address(ip)
            respuesta = self.resolver.resolve(rev_name, "PTR")
            return [str(r) for r in respuesta]
        except Exception as e:
            return [f"Error en PTR lookup: {e}"]

    def enumerate_all(self, target):
        """Enumera todos los tipos de registros definidos."""
        self.results = {}
        for record_type in self.record_types:
            data = self.resolve_domain(target, record_type)
            self.results[record_type] = data
            self.print_section(record_type, target, data)

    def enumerate_selected(self, target, selected_types):
        """Enumera solo los tipos seleccionados."""
        self.results = {}
        for record_type in selected_types:
            data = self.resolve_domain(target, record_type)
            self.results[record_type] = data
            self.print_section(record_type, target, data)

    def print_section(self, record_type, target, data):
        """Muestra resultados en formato legible."""
        print(f"\n===== {record_type} records for {target} =====")
        for entry in data:
            print(entry)

    def export_results(self, filename, fmt):
        """Exporta resultados a .txt, .json o .html."""
        abs_path = os.path.abspath(filename)

        try:
            if fmt == "txt":
                with open(filename, "w", encoding="utf-8") as f:
                    for rtype, values in self.results.items():
                        f.write(f"===== {rtype} =====\n")
                        for v in values:
                            f.write(f"{v}\n")
                        f.write("\n")

            elif fmt == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.results, f, indent=4, ensure_ascii=False)

            elif fmt == "html":
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("<html><body><h1>Resultados DNS</h1>")
                    for rtype, values in self.results.items():
                        f.write(f"<h2>{rtype}</h2><ul>")
                        for v in values:
                            f.write(f"<li>{v}</li>")
                        f.write("</ul>")
                    f.write("</body></html>")

            print(f"[+] Resultados exportados en: {abs_path}")

        except Exception as e:
            print(f"[X] Error exportando resultados: {e}")


if __name__ == "__main__":
    dns_enum = DNSEnumerator()

    print("""
    [1] Enumerar TODOS los registros DNS
    [2] Elegir tipos de registros específicos
    [3] Resolución inversa (PTR lookup)
    """)

    opcion = input("Selecciona una opción: ")

    if opcion == "1":
        target = input("Dominio objetivo: ").strip()
        dns_enum.enumerate_all(target)

    elif opcion == "2":
        target = input("Dominio objetivo: ").strip()
        print("\nTipos disponibles:", ", ".join(dns_enum.record_types))
        tipos = input("Introduce los tipos separados por coma (ej: A,MX,TXT): ").upper().replace(" ", "").split(",")
        dns_enum.enumerate_selected(target, tipos)

    elif opcion == "3":
        ip = input("Dirección IP: ").strip()
        data = dns_enum.reverse_lookup(ip)
        dns_enum.results = {"PTR": data}
        dns_enum.print_section("PTR", ip, data)

    else:
        print("[X] Opción no válida.")
        exit()

    # Opción de exportar resultados
    exportar = input("\n¿Exportar resultados? (s/n): ").lower()
    if exportar == "s":
        formato = input("Formato (txt/json/html): ").lower()
        if formato not in ["txt", "json", "html"]:
            print("[X] Formato no válido.")
        else:
            nombre_archivo = f"dns_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{formato}"
            dns_enum.export_results(nombre_archivo, formato)
