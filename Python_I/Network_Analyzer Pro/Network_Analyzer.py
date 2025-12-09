#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network_Analyzer.py
Analizador de red tipo nmap con foco en sigilo y usabilidad.

Características:
- Scan silencioso por perfiles (-sS, tiempos conservadores).
- Soporte TCP/UDP, rango de puertos custom, o todos los puertos.
- Detección TTL (ICMP) para estimar OS (aprox: 64 ≈ Linux/Unix-like, 128 ≈ Windows).
- Parseo XML de Nmap (-oX -) para tabla limpia: host, puerto, estado, servicio, versión.
- 2da fase opcional: escaneo profundo en puertos abiertos (-sV, --script "default,vuln").
- Manejo básico de puertos "filtered": reintento con perfil más sigiloso.
- Exportación a HTML/TXT con ruta absoluta.
"""

import os
import sys
import subprocess
import shlex
from pathlib import Path
from datetime import datetime
from xml.etree import ElementTree as ET
from typing import List, Dict, Tuple, Optional

# Opcional: colores lindos en CLI
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _F:  # fallback si no está colorama
        GREEN=BLUE=YELLOW=RED=CYAN=MAGENTA=""
        RESET=""
    Fore = _F()
    Style = _F()

# TTL ping (mejor con root). Si no hay permisos, se omite silenciosamente.
def ttl_probe(host: str, timeout: int = 2) -> Optional[int]:
    try:
        # Intento ICMP con ping del sistema (más portable que raw sockets sin root)
        # -c1: 1 paquete ; -W timeout (en Linux). En Windows sería distinto; asumimos entorno *nix.
        cmd = f"ping -c 1 -W {timeout} {shlex.quote(host)}"
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = p.stdout
        # Buscar 'ttl=N'
        for line in out.splitlines():
            line = line.lower()
            if "ttl=" in line:
                # ... ttl=64 ...
                try:
                    ttl_str = line.split("ttl=")[1].split()[0]
                    return int(ttl_str)
                except Exception:
                    pass
    except Exception:
        pass
    return None

def ttl_guess(ttl: Optional[int]) -> str:
    if ttl is None:
        return "Desconocido"
    # Aproximación grosera: muchos *nix usan 64, Windows 128 (a veces 255 en algunos equipos)
    if ttl >= 110:
        return f"Windows-like (ttl={ttl})"
    elif 50 <= ttl <= 70:
        return f"Linux/Unix-like (ttl={ttl})"
    else:
        return f"Indeterminado (ttl={ttl})"

STEALTH_PROFILES = {
    # perfil: flags y tiempos. Todos son -Pn y -n para reducir “ruido” y resolución DNS.
    "silent": ["-sS", "-T2", "--max-retries", "2", "--scan-delay", "30ms", "--defeat-rst-ratelimit", "-Pn", "-n"],
    "balanced": ["-sS", "-T3", "--max-retries", "3", "-Pn", "-n"],
    "aggressive": ["-sS", "-T4", "--max-retries", "1", "-Pn", "-n"],
}

def build_nmap_cmd(
    target: str,
    tcp: bool = True,
    udp: bool = False,
    ports: Optional[str] = None,
    profile: str = "silent",
    service_version: bool = False,
    os_detect: bool = False,
    scripts: Optional[str] = None,
    extra: Optional[List[str]] = None,
    xml_stdout: bool = True,
) -> List[str]:
    cmd = ["nmap"]
    # Perfil
    cmd += STEALTH_PROFILES.get(profile, STEALTH_PROFILES["silent"])

    # TCP/UDP
    if udp and not tcp:
        cmd = [c for c in cmd if c != "-sS"]  # sacamos -sS si venía del perfil
        cmd.insert(1, "-sU")
    elif udp and tcp:
        # escaneo combinado: TCP SYN + UDP top 100 por defecto (o lo que el user pase)
        # Podemos dejar ambos habilitados; nmap maneja múltiple protocolo.
        cmd.append("-sU")

    # Puertos
    if ports:
        cmd += ["-p", ports]
    else:
        # por defecto algo prudente: top 1000 TCP (por perfil) — si querés TODOS: "-p-"
        pass

    # Service/Version y OS
    if service_version:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")

    # Scripts NSE (mantenemos safe: default,vuln)
    if scripts:
        cmd += ["--script", scripts]

    # Salida XML a stdout para parseo
    if xml_stdout:
        cmd += ["-oX", "-"]

    # Extras
    if extra:
        cmd += extra

    cmd.append(target)
    return cmd

def run_nmap(cmd: List[str]) -> Tuple[str, str, int]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout, proc.stderr, proc.returncode

def parse_nmap_xml(xml_text: str) -> List[Dict]:
    """
    Devuelve una lista de hosts:
    [
      {
        "address": "1.2.3.4",
        "hostname": "...",
        "ports": [
           {"port": "80/tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0", "extrainfo": ""}
        ],
        "os": "..." (si hay)
      },
      ...
    ]
    """
    results = []
    if not xml_text.strip():
        return results
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in ("up", "open"):
            continue

        addresses = host.findall("address")
        addr = ""
        for a in addresses:
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break

        hostname = ""
        hn = host.find("hostnames")
        if hn is not None:
            h = hn.find("hostname")
            if h is not None and h.get("name"):
                hostname = h.get("name")

        # OS (si hay fingerprint)
        os_match = ""
        os_node = host.find("os")
        if os_node is not None:
            # tomamos el primer osmatch con mayor accuracy
            best = None
            for om in os_node.findall("osmatch"):
                acc = int(om.get("accuracy", "0"))
                if not best or acc > best[0]:
                    best = (acc, om.get("name", ""))
            if best:
                os_match = f"{best[1]} (accuracy {best[0]}%)"

        ports_node = host.find("ports")
        ports = []
        if ports_node is not None:
            for p in ports_node.findall("port"):
                proto = p.get("protocol", "tcp")
                portid = p.get("portid", "")
                state = p.find("state").get("state") if p.find("state") is not None else ""
                service = p.find("service")
                svc_name = service.get("name") if service is not None else ""
                product = service.get("product") if service is not None and service.get("product") else ""
                version = service.get("version") if service is not None and service.get("version") else ""
                extrainfo = service.get("extrainfo") if service is not None and service.get("extrainfo") else ""
                ports.append({
                    "port": f"{portid}/{proto}",
                    "state": state,
                    "service": svc_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo
                })

        results.append({
            "address": addr,
            "hostname": hostname,
            "ports": ports,
            "os": os_match
        })
    return results

def pretty_cli_host(host: Dict, ttl_guess_str: str = ""):
    head = f"{Fore.CYAN}Host: {host['address']} {Fore.MAGENTA}{'(' + host['hostname'] + ')' if host['hostname'] else ''}{Style.RESET_ALL}"
    print(head)
    if host.get("os"):
        print(f"  {Fore.YELLOW}OS (nmap):{Style.RESET_ALL} {host['os']}")
    if ttl_guess_str:
        print(f"  {Fore.YELLOW}OS (TTL aprox):{Style.RESET_ALL} {ttl_guess_str}")
    if not host["ports"]:
        print(f"  {Fore.RED}No hay puertos reportados por nmap para este host.{Style.RESET_ALL}")
        return
    print(f"  {Fore.GREEN}Puertos/Servicios:{Style.RESET_ALL}")
    print("  {:<10} {:<10} {:<15} {:<15} {}".format("PUERTO", "ESTADO", "SERVICIO", "PRODUCTO", "VERSION"))
    for p in host["ports"]:
        print("  {:<10} {:<10} {:<15} {:<15} {}".format(
            p["port"], p["state"], p["service"], p["product"][:14], (p["version"] or p["extrainfo"])
        ))
    print()

def export_html(report_path: Path, all_hosts: List[Dict], ttl_map: Dict[str, str]):
    rows = []
    for h in all_hosts:
        ttl_str = ttl_map.get(h["address"], "")
        if not h["ports"]:
            rows.append(f"<tr><td>{h['address']}</td><td>{h['hostname']}</td><td>-</td><td>-</td><td>-</td><td>{h.get('os','')}</td><td>{ttl_str}</td></tr>")
            continue
        for p in h["ports"]:
            rows.append(
                f"<tr>"
                f"<td>{h['address']}</td>"
                f"<td>{h['hostname']}</td>"
                f"<td>{p['port']}</td>"
                f"<td>{p['state']}</td>"
                f"<td>{p['service']} {p['product']} {p['version']}</td>"
                f"<td>{h.get('os','')}</td>"
                f"<td>{ttl_str}</td>"
                f"</tr>"
            )
    html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<title>Network Analyzer Report</title>
<style>
body{{font-family:Arial,Helvetica,sans-serif;margin:20px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px}}
th{{background:#f4f4f4;text-align:left}}
h1{{margin-bottom:4px}}
.small{{color:#777}}
</style>
</head>
<body>
<h1>Network Analyzer Report</h1>
<div class="small">Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
<table>
<thead>
<tr>
<th>Host</th><th>Hostname</th><th>Puerto</th><th>Estado</th><th>Servicio</th><th>OS (nmap)</th><th>OS (TTL aprox)</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
    report_path.write_text(html, encoding="utf-8")
    return str(report_path.resolve())

class NetworkAnalyzer:
    def __init__(self, out_dir: str = "NA_Reports"):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(exist_ok=True)
        self.ttl_cache: Dict[str, str] = {}  # host -> ttl guess string

    def scan(
        self,
        targets: List[str],
        tcp: bool = True,
        udp: bool = False,
        ports: Optional[str] = None,
        profile: str = "silent",
        detect_os: bool = False,
        show_version: bool = True,
        html_report: bool = False,
        retry_filtered: bool = True,
    ) -> Tuple[List[Dict], Optional[str], Optional[str]]:
        """
        Retorna: (hosts_parseados, ruta_html, ruta_txt_raw)
        """
        all_hosts: List[Dict] = []
        raw_txt_parts: List[str] = []
        # TTL probe por target (mejor antes de -Pn para no levantar ICMP floods)
        for t in targets:
            ttl = ttl_probe(t)
            self.ttl_cache[t] = ttl_guess(ttl)

        for target in targets:
            cmd = build_nmap_cmd(
                target=target,
                tcp=tcp,
                udp=udp,
                ports=ports,
                profile=profile,
                service_version=show_version,
                os_detect=detect_os,
                scripts=None,
                extra=None,
                xml_stdout=True
            )
            stdout, stderr, rc = run_nmap(cmd)
            raw_txt_parts.append(f"$ {' '.join(cmd)}\n{stdout}\n{stderr}\n")

            hosts = parse_nmap_xml(stdout)
            # Si la mayoría de puertos salen filtered, intentamos un reintento con aún más sigilo
            if retry_filtered and hosts and all(
                (not h["ports"] or all(p["state"] == "filtered" for p in h["ports"])) for h in hosts
            ):
                stealthier = build_nmap_cmd(
                    target=target,
                    tcp=tcp,
                    udp=udp,
                    ports=ports,
                    profile="silent",
                    service_version=False,  # menos ruido
                    os_detect=False,
                    scripts=None,
                    extra=["--scan-delay", "60ms", "--max-retries", "1"],
                    xml_stdout=True
                )
                stdout2, stderr2, rc2 = run_nmap(stealthier)
                raw_txt_parts.append(f"$ {' '.join(stealthier)}\n{stdout2}\n{stderr2}\n")
                hosts2 = parse_nmap_xml(stdout2)
                # Si en el reintento aparecen open/closed más claros, usamos la mezcla mejor
                if hosts2:
                    hosts = hosts2

            all_hosts.extend(hosts)

        # Exportaciones
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        raw_path = self.out_dir / f"network_analyzer_raw_{timestamp}.txt"
        raw_path.write_text("\n".join(raw_txt_parts), encoding="utf-8")
        html_path = None
        if html_report:
            html_path = export_html(self.out_dir / f"network_analyzer_{timestamp}.html", all_hosts, self.ttl_cache)

        return all_hosts, (html_path or None), str(raw_path.resolve())

    def deep_scan(
        self,
        host: str,
        open_ports: List[str],
        profile: str = "silent",
        scripts: str = "default,vuln",
        service_version: bool = True,
        os_detect: bool = False,
    ) -> List[Dict]:
        """
        2da fase sobre puertos abiertos de un host concreto.
        """
        if not open_ports:
            return []
        # Formato nmap -p "80,443,22"
        ports_arg = ",".join([p.split("/")[0] for p in open_ports])
        cmd = build_nmap_cmd(
            target=host,
            tcp=True,
            udp=False,
            ports=ports_arg,
            profile=profile,
            service_version=service_version,
            os_detect=os_detect,
            scripts=scripts,  # seguro: "default,vuln"
            extra=None,
            xml_stdout=True
        )
        stdout, stderr, rc = run_nmap(cmd)
        return parse_nmap_xml(stdout)
