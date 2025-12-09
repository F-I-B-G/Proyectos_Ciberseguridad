# main.py
import os
from nmap_parser import parse_nmap_xml
from utils.service_cleaner import clean_service
from vulnerability_scanner import VulnerabilityScanner
from html_exporter import export_html

def main():
    print("== Vulnerability Scanner (usa NVD + CveDetails) ==")
    archivo = input("Ingresá la ruta del archivo XML exportado por Nmap (-oX): ").strip()
    if not os.path.isfile(archivo):
        print("No existe el archivo indicado.")
        return

    servicios = parse_nmap_xml(archivo)
    if not servicios:
        print("No se detectaron servicios en el XML.")
        return

    print(f"Se detectaron {len(servicios)} servicios. Ejemplos: {servicios[:5]}")
    scanner = VulnerabilityScanner()

    all_results = []
    for servicio_raw in servicios:
        servicio = clean_service(servicio_raw)
        print(f"\nBuscando CVEs para: {servicio} (raw: {servicio_raw})")
        cves = scanner.search_cves(servicio)
        if not cves:
            print("  -> No se encontraron CVEs o la consulta falló.")
            continue
        scanner.pretty_print(cves)
        # agregar campo servicio para export
        for c in cves:
            c["_service"] = servicio
        all_results.extend(cves)

    # preguntar si exportar HTML
    if all_results:
        salida = input("\n¿Querés exportar TODO a HTML? (s/n): ").strip().lower()
        if salida == "s":
            export_html(all_results, service_name="Resultados Nmap", output_path="reporte.html")
    else:
        print("No hay resultados para exportar.")

if __name__ == "__main__":
    main()
