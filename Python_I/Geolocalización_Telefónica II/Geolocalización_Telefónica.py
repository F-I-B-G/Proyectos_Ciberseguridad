"""
Geolocalización_Telefónica.py
--------------------------------
Herramienta para obtener información básica y ubicación aproximada de un número de teléfono.

FUNCIONES DISPONIBLES:
1 - Obtener información general: país, operador, zona horaria y formato internacional.
2 - Generar mapa con la ubicación aproximada.
3 - Exportar resultados en .txt / .json / .html.
4 - Manejo de errores y validaciones para evitar fallos con números inválidos.

REQUISITOS:
- phonenumbers
- geopy
- folium
"""

import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import folium
from geopy.geocoders import Photon
import json
import os
import sys


def obtener_informacion_telefonica(numero_telefonico):
    """
    Obtiene país, operador, zona horaria y formato internacional de un número de teléfono.
    """
    try:
        numero = phonenumbers.parse(numero_telefonico)

        zona_horaria = timezone.time_zones_for_number(numero) or ["Desconocida"]
        pais = geocoder.description_for_number(numero, 'es') or "Desconocido"
        operador = carrier.name_for_number(numero, 'es') or "Desconocido"

        return {
            'Número': phonenumbers.format_number(numero, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'País': pais,
            'Operador': operador,
            'Zona Horaria': zona_horaria
        }
    except phonenumbers.phonenumberutil.NumberParseException:
        print("Número de teléfono inválido. Asegúrate de incluir el código de país (+54...).")
        sys.exit(1)


def mostrar_mapa(localizacion, filename='mapa_telefonico.html'):
    """
    Genera un mapa HTML con marcador de la localización estimada.
    """
    geolocalizador = Photon(user_agent='Geolocalizacion_Telefonica')
    loc_data = geolocalizador.geocode(localizacion)

    if loc_data is None:
        print(f"No se pudo geolocalizar: {localizacion}")
        return None

    mapa = folium.Map(location=[loc_data.latitude, loc_data.longitude], zoom_start=10)
    folium.Marker([loc_data.latitude, loc_data.longitude], popup=localizacion).add_to(mapa)
    mapa.save(filename)

    ruta_abs = os.path.abspath(filename)
    print(f"Mapa guardado en: {ruta_abs}")
    return ruta_abs


def exportar_resultados(datos, formato, nombre_base="resultados"):
    """
    Exporta la información obtenida en formato .txt, .json o .html.
    """
    if formato == "txt":
        nombre_archivo = f"{nombre_base}.txt"
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            for clave, valor in datos.items():
                f.write(f"{clave}: {valor}\n")
    elif formato == "json":
        nombre_archivo = f"{nombre_base}.json"
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            json.dump(datos, f, indent=4, ensure_ascii=False)
    elif formato == "html":
        nombre_archivo = f"{nombre_base}.html"
        with open(nombre_archivo, "w", encoding="utf-8") as f:
            f.write("<html><body><h2>Resultados de geolocalización</h2><ul>")
            for clave, valor in datos.items():
                f.write(f"<li><b>{clave}:</b> {valor}</li>")
            f.write("</ul></body></html>")
    else:
        print("Formato no soportado.")
        return None

    ruta_abs = os.path.abspath(nombre_archivo)
    print(f"Resultados exportados en: {ruta_abs}")
    return ruta_abs


if __name__ == '__main__':
    numero = input('Introduce un número telefónico (ej: "+549..."): ')
    datos = obtener_informacion_telefonica(numero)

    print("\nInformación obtenida:")
    for k, v in datos.items():
        print(f"{k}: {v}")

    print("\n--- OPCIONES ---")
    print("1 - Solo mostrar información")
    print("2 - Mostrar información + generar mapa")
    print("3 - Mostrar información + exportar resultados")
    print("4 - Mostrar información + generar mapa + exportar")
    opcion = input("Selecciona una opción (1-4): ")

    if opcion == "2" or opcion == "4":
        mostrar_mapa(datos['País'])

    if opcion == "3" or opcion == "4":
        print("\nFormatos disponibles: txt / json / html")
        formato = input("Selecciona el formato de exportación: ").lower()
        exportar_resultados(datos, formato)
