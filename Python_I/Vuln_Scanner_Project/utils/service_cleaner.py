# utils/service_cleaner.py
import re

def clean_service(service: str) -> str:
    """
    Limpia y normaliza el nombre de servicio para buscar en NVD.
    Ej: "OpenSSH 8.4p1 Debian" -> "OpenSSH 8.4"
    """
    if not service:
        return service

    # Sacar paréntesis y contenido entre ellos
    s = re.sub(r"\(.*?\)|\[.*?\]", "", service)
    s = " ".join(s.split())  # compacta espacios
    parts = s.split()

    # Si la segunda parte contiene letras (ej 8.4p1) reemplazamos p1 por nada y tomamos números y puntos
    if len(parts) >= 2:
        # extraer la porción numérica de la versión (ej 1.3.5e -> 1.3.5)
        ver = re.match(r"(\d+(?:\.\d+){0,})", parts[1])
        version = ver.group(1) if ver else parts[1]
        name = parts[0]
        return f"{name} {version}"
    return parts[0]
