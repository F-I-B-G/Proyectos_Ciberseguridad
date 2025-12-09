# nmap_parser.py
import xml.etree.ElementTree as ET

def parse_nmap_xml(path):
    """
    Devuelve lista de servicios detectados por Nmap con nombre y versión (raw).
    Solo acepta XML (output -oX de nmap).
    """
    servicios = set()
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        raise ValueError(f"Error parseando XML: {e}")
    root = tree.getroot()

    # Nmap XML tiene hosts -> ports -> port -> service
    for host in root.findall("host"):
        for port in host.findall("ports/port"):
            service = port.find("service")
            if service is None:
                continue
            name = service.get("name")
            version = service.get("version")
            product = service.get("product")
            # Preferimos version si existe, si no product, si no name
            descriptor = None
            if name and version:
                descriptor = f"{name} {version}"
            elif name and product:
                descriptor = f"{name} {product}"
            elif name:
                descriptor = name
            if descriptor:
                servicios.add(descriptor.strip())
    return list(servicios)
