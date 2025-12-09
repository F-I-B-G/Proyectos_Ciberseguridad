import cv2
import argparse
from bitarray import bitarray
import numpy as np

class InfoHidder:
    def __init__(self, nombre_imagen):
        self.imagen = cv2.imread(nombre_imagen)
        if self.imagen is None:
            raise ValueError(f"[!] No se pudo cargar la imagen: {nombre_imagen}")
        self.n_bits = self.imagen.size  # número total de bits disponibles
        print(f"[*] Máximo número de bits a codificar: {self.n_bits}")

    def a_binario(self, datos):
        ba = bitarray()
        ba.frombytes(datos.encode() if isinstance(datos, str) else bytes(datos))
        return ba

    def codificar(self, datos_secretos):
        datos_binarios = self.a_binario(f"{datos_secretos}====")
        if len(datos_binarios) > self.n_bits:
            raise ValueError("[!] Bits insuficientes, se necesita una imagen más grande.")
        
        indice_datos = 0
        for pixel in self.imagen.reshape(-1, 3):
            for i in range(3):
                if indice_datos >= len(datos_binarios):
                    break
                pixel[i] = np.uint8((int(pixel[i]) & ~1) | int(datos_binarios[indice_datos]))
                indice_datos += 1
            if indice_datos >= len(datos_binarios):
                break

    def guardar_imagen(self, nombre_salida):
        cv2.imwrite(nombre_salida, self.imagen)

    def decodificar(self):
        datos_binarios = bitarray()
        datos_binarios.extend((pixel & 1 for pixel in self.imagen.reshape(-1, 3).ravel()))
        datos_decodificados = datos_binarios.tobytes().decode(errors='ignore')
        return datos_decodificados.split("====", 1)[0]

def main():
    parser = argparse.ArgumentParser(description="Codifica y decodifica mensajes secretos en imágenes.")
    parser.add_argument("accion", choices=["codificar", "decodificar"])
    parser.add_argument("nombre_entrada")
    parser.add_argument("--mensaje", help="Mensaje secreto a codificar")
    parser.add_argument("--nombre-salida", help="Nombre del archivo de salida")

    args = parser.parse_args()
    hidder = InfoHidder(args.nombre_entrada)

    if args.accion == 'codificar':
        if not args.mensaje:
            parser.error("[+] Debe proporcionar un mensaje secreto a codificar.")
        hidder.codificar(args.mensaje)
        hidder.guardar_imagen(args.nombre_salida or "imagen_codificada.png")
    else:
        print(f"[*] Datos decodificados: {hidder.decodificar()}")

if __name__ == "__main__":
    main()

"""
- Codificar:

python info_hidder.py codificar /home/kali/Desktop/test.png --mensaje "Hola" --nombre-salida salida.png

- Decodificar:

python info_hidder.py decodificar salida.png
"""