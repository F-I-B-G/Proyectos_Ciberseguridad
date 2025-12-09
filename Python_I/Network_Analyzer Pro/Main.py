#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main.py
Interfaz CLI para Network_Analyzer.
"""

from pathlib import Path
from Network_Analyzer import NetworkAnalyzer, pretty_cli_host, Fore, Style

def ask_list(prompt: str) -> list:
    s = input(prompt).strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def main():
    print(f"{Fore.MAGENTA}\n=== Network Analyzer (sigiloso) ==={Style.RESET_ALL}")

    # Targets
    choice = input("¿Querés cargar targets desde archivo? (y/N): ").strip().lower()
    targets = []
    if choice == "y":
        path = input("Ruta del .txt (uno por línea, acepta IP/CIDR/Dominio): ").strip()
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        targets = [l.strip() for l in lines if l.strip()]
    else:
        targets = ask_list("Ingresá targets separados por coma (IP/CIDR/Dominio): ")

    if not targets:
        print("No se ingresaron targets. Chao.")
        return

    # Protocolos
    proto = input("Protocolo [1=TCP (default), 2=UDP, 3=TCP+UDP]: ").strip()
    tcp = True; udp = False
    if proto == "2":
        tcp, udp = False, True
    elif proto == "3":
        tcp, udp = True, True

    # Puertos
    ports = input("Puertos (ej: 22,80,443 o rango 1-1024 o -p- para todos) [enter=top por defecto]: ").strip()
    ports = None if not ports or ports.lower()=="top" else (None if ports=="" else ports.replace("-p-", "1-65535"))

    # Perfil
    print("\nPerfiles de sigilo:")
    print("  1) silent (muy discreto)  2) balanced  3) aggressive")
    pf = input("Elegí perfil [1/2/3] (default=1): ").strip()
    profile = {"1":"silent","2":"balanced","3":"aggressive"}.get(pf, "silent")

    # Detección OS y versiones
    detect_os = input("¿Intentar identificar OS con nmap -O? (y/N): ").strip().lower() == "y"
    show_version = input("¿Detectar versiones de servicio -sV? (Y/n): ").strip().lower() != "n"

    # Exportación
    html_report = input("¿Exportar reporte HTML? (Y/n): ").strip().lower() != "n"

    analyzer = NetworkAnalyzer(out_dir="NA_Reports")

    print(f"\n{Fore.CYAN}[*] Ejecutando escaneo inicial...{Style.RESET_ALL}")
    hosts, html_path, raw_path = analyzer.scan(
        targets=targets,
        tcp=tcp,
        udp=udp,
        ports=ports,
        profile=profile,
        detect_os=detect_os,
        show_version=show_version,
        html_report=html_report,
        retry_filtered=True
    )

    if not hosts:
        print(f"{Fore.RED}[!] No se obtuvieron resultados. Revisá conectividad/permisos.{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.GREEN}[+] Resultados:{Style.RESET_ALL}\n")
        for h in hosts:
            ttl_guess_str = analyzer.ttl_cache.get(h["address"], "")
            pretty_cli_host(h, ttl_guess_str)

    if html_path:
        print(f"{Fore.GREEN}[+] HTML guardado en:{Style.RESET_ALL} {html_path}")
    print(f"{Fore.GREEN}[+] RAW TXT guardado en:{Style.RESET_ALL} {raw_path}")

    # Post-scan
    go_deep = input("\n¿Hacer escaneo profundo de puertos abiertos con scripts seguros (default,vuln)? (y/N): ").strip().lower() == "y"
    if go_deep and hosts:
        for h in hosts:
            open_ports = [p["port"] for p in h["ports"] if p["state"] == "open"]
            if not open_ports:
                continue
            print(f"\n{Fore.CYAN}[*] Deep scan en {h['address']} sobre {len(open_ports)} puertos...{Style.RESET_ALL}")
            deep = analyzer.deep_scan(
                host=h["address"],
                open_ports=open_ports,
                profile=profile,
                scripts="default,vuln",
                service_version=True,
                os_detect=False
            )
            for dh in deep:
                pretty_cli_host(dh, analyzer.ttl_cache.get(dh["address"], ""))

    print(f"\n{Fore.MAGENTA}Listo, papá. B){Style.RESET_ALL}")

if __name__ == "__main__":
    main()
