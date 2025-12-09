import subprocess
import re
import random

class MACSpoofing: # Clase para realizar operaciones de spoofing de direcciones MAC en una interfaz de red específica.

    def __init__(self, interface):
        self.interface = interface
        self.mac_file = f"{self.interface}_mac.txt" # Para saber cuál era mi MAC original

    def read_mac_from_file(self):# Lee la dirección MAC almacenada en un archivo.
        try:
            with open(self.mac_file, 'r') as file:
                return file.read().strip()
        except FileNotFoundError:
            print('[!] No se pudo encontrar el archivo')
            return None

    def write_mac_to_file(self, mac): # Escribe una dirección MAC en un archivo.
        with open(self.mac_file, 'w') as file:
            file.write(mac)

    def get_current_mac(self): # Obtiene la dirección MAC actual de la interfaz de red.
        try:
            result = subprocess.check_output(["ifconfig", self.interface]) # Ejecutamos el comando en nuestro OS para mostrar las interfaces en Linux
            mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(result)) # 'w\w:w\w:' es el patrón que debería seguir la MAC. Podría ir cualquier letra mientras siga el patrón
            if mac_address:
                return mac_address.group(0)
            else:
                raise ValueError("[!] No se pudo obtener la dirección MAC.")
        except subprocess.CalledProcessError: # Error que nos indica que el comando no pudo ser ejecutado porque el SO no tiene instalada la utilidad que se requiere
            raise ValueError("[!] No se pudo ejecutar ifconfig.")

    def change_mac(self, new_mac):# Cambia la dirección MAC de la interfaz de red.
        subprocess.call(["sudo", "ifconfig", self.interface, "down"]) # Deja la interfaz inactiva para realizar cambios sobre ella
        subprocess.call(["sudo", "ifconfig", self.interface, "hw", "ether", new_mac]) # Cambia la MAC a la nueva
        subprocess.call(["sudo", "ifconfig", self.interface, "up"]) # Vuelve a activar la interfaz

    def validate_mac(self, mac): # Valida el formato de una dirección MAC para evitar una MAC errónea que nos impida la comunicación en la red

        return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac))

    def generate_random_mac(self): # Genera una dirección MAC aleatoria válida.
        return "02:%02x:%02x:%02x:%02x:%02x" % ( # Arranca con el caracter '02' por defecto y luego hexadecimales
            random.randint(0, 127),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
