"""
Herramienta de Geolocalización IP usando la API gratuita de ipinfo.io

FUNCIONALIDADES:
[1] Consultar una IP específica → Muestra información y genera un mapa.
[2] Consultar múltiples IPs desde archivo .txt → Muestra info y crea un mapa con todas las ubicaciones.
[3] Consultar tu IP pública → Usa ipinfo para obtener tu propia IP y datos.

Al final de cada consulta se puede exportar el resultado a:
    - .txt  → salida simple
    - .json → formato estructurado
    - .html → mapa interactivo (uno o varios puntos)
"""

import ipinfo
from dotenv import load_dotenv
import os
import sys
import folium
import json
import requests
from datetime import datetime
import ipaddress

# ===============================
# CONFIGURACIÓN Y CARGA DE TOKEN
# ===============================
load_dotenv()
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')

if not ACCESS_TOKEN:
    print("[X] No se encontró ACCESS_TOKEN en el archivo .env")
    sys.exit(1)

# ===============================
# FUNCIONES AUXILIARES
# ===============================
def validar_ip(ip_str):
    """Valida si una cadena es una IP válida."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def localizacion_en_mapa(marcadores, nombre_fichero='mapa.html'):
    """
    Dibuja un mapa con uno o varios marcadores.
    marcadores: lista de tuplas (lat, lon, descripcion)
    """
    if not marcadores:
        print("[!] No hay coordenadas para generar el mapa.")
        return None

    # Centrar mapa en el primer marcador
    lat0, lon0, _ = marcadores[0]
    mapa = folium.Map(location=[lat0, lon0], zoom_start=4)

    for lat, lon, desc in marcadores:
        folium.Marker([lat, lon], popup=desc).add_to(mapa)

    mapa.save(nombre_fichero)
    return os.path.abspath(nombre_fichero)

def get_ip_details(direccion_ip, token):
    """Obtiene detalles de una IP usando ipinfo.io"""
    try:
        cliente = ipinfo.getHandler(token)
        detalles = cliente.getDetails(direccion_ip)
        return detalles.all
    except Exception as e:
        return {"error": str(e)}

def exportar_resultados(datos, formato):
    """Exporta resultados a txt o json"""
    filename = f"ip_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{formato}"
    abs_path = os.path.abspath(filename)

    try:
        if formato == "txt":
            with open(filename, "w", encoding="utf-8") as f:
                for entry in datos:
                    f.write("="*40 + "\n")
                    for k, v in entry.items():
                        f.write(f"{k}: {v}\n")

        elif formato == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(datos, f, indent=4, ensure_ascii=False)

        print(f"[+] Resultados exportados en: {abs_path}")
    except Exception as e:
        print(f"[X] Error exportando resultados: {e}")

# ===============================
# MENÚ PRINCIPAL
# ===============================
if __name__ == "__main__":
    print("""
    [1] Consultar una IP específica
    [2] Consultar múltiples IPs desde archivo .txt
    [3] Consultar mi IP pública
    """)

    opcion = input("Selecciona una opción: ")

    resultados = []
    marcadores = []

    if opcion == "1":
        ip = input("Introduce la IP que deseas localizar: ").strip()
        if not validar_ip(ip):
            print("[X] IP no válida.")
            sys.exit(1)

        detalles = get_ip_details(ip, ACCESS_TOKEN)
        resultados.append(detalles)

        lat = detalles.get('latitude')
        lon = detalles.get('longitude')
        ubicacion = f"{detalles.get('city', '')}, {detalles.get('region', '')}, {detalles.get('country', '')}"
        if lat and lon:
            marcadores.append((float(lat), float(lon), ubicacion))
            ruta_mapa = localizacion_en_mapa(marcadores)
            if ruta_mapa:
                print(f"[+] Mapa guardado en: {ruta_mapa}")

    elif opcion == "2":
        ruta_archivo = input("Ruta del archivo .txt con IPs: ").strip()
        if not os.path.exists(ruta_archivo):
            print("[X] Archivo no encontrado.")
            sys.exit(1)

        with open(ruta_archivo, "r", encoding="utf-8") as f:
            ips = [line.strip() for line in f if line.strip()]

        for ip in ips:
            if validar_ip(ip):
                detalles = get_ip_details(ip, ACCESS_TOKEN)
                resultados.append(detalles)
                lat = detalles.get('latitude')
                lon = detalles.get('longitude')
                ubicacion = f"{detalles.get('city', '')}, {detalles.get('region', '')}, {detalles.get('country', '')}"
                if lat and lon:
                    marcadores.append((float(lat), float(lon), ubicacion))
            else:
                print(f"[!] IP inválida: {ip}")

        if marcadores:
            ruta_mapa = localizacion_en_mapa(marcadores)
            if ruta_mapa:
                print(f"[+] Mapa guardado en: {ruta_mapa}")

    elif opcion == "3":
        try:
            mi_ip = requests.get("https://ipinfo.io/ip").text.strip()
            print(f"[+] Tu IP pública: {mi_ip}")
            detalles = get_ip_details(mi_ip, ACCESS_TOKEN)
            resultados.append(detalles)

            lat = detalles.get('latitude')
            lon = detalles.get('longitude')
            ubicacion = f"{detalles.get('city', '')}, {detalles.get('region', '')}, {detalles.get('country', '')}"
            if lat and lon:
                marcadores.append((float(lat), float(lon), ubicacion))
                ruta_mapa = localizacion_en_mapa(marcadores)
                if ruta_mapa:
                    print(f"[+] Mapa guardado en: {ruta_mapa}")
        except Exception as e:
            print(f"[X] No se pudo obtener la IP pública: {e}")

    else:
        print("[X] Opción no válida.")
        sys.exit(1)

    # ===============================
    # OPCIÓN DE EXPORTACIÓN
    # ===============================
    if resultados:
        exportar = input("¿Exportar resultados? (s/n): ").lower()
        if exportar == "s":
            formato = input("Formato (txt/json): ").lower()
            if formato in ["txt", "json"]:
                exportar_resultados(resultados, formato)
            else:
                print("[X] Formato no válido.")
