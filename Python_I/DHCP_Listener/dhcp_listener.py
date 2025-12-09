from scapy.all import *
import time

class DHCPListener: # Clase para escuchar y procesar paquetes DHCP en la red.

    def iniciar_escucha(self):
        
        # Inicia la escucha de tráfico DHCP en la red.
        
        print("[+] Iniciando la escucha de tráfico DHCP en la red...")
        sniff(prn=self.procesar_paquete, filter="udp and (port 67 or port 68)") # Utiliza la función `sniff` de Scapy para capturar paquetes UDP en los puertos 67 y 68.

    def procesar_paquete(self, paquete): # Si se captura un paquete DHCP, lo va a procesar para extraerle información
        if DHCP in paquete:
            detalles_dhcp = self.extraer_detalles(paquete)
            if all(value is None for value in detalles_dhcp.values()):
                return
            self.mostrar_informacion(detalles_dhcp)

    def extraer_detalles(self, paquete): # Se van a extraer los detalles que nos parezcan más relevantes
        detalles = {
            "mac_destino": paquete[Ether].src if Ether in paquete else None,
            "ip_solicitada": None,
            "nombre_host": None,
            "id_vendedor": None # Versión específica del sistema que recibe el host
        }

        for opcion in paquete[DHCP].options:
            if isinstance(opcion, tuple) and len(opcion) == 2:
                etiqueta, valor = opcion
                if etiqueta == 'requested_addr':
                    detalles['ip_solicitada'] = valor
                elif etiqueta == 'hostname':
                    detalles['nombre_host'] = valor.decode(errors='ignore')
                elif etiqueta == 'vendor_class_id':
                    detalles['id_vendedor'] = valor.decode(errors='ignore')
        
        return detalles
    
    def mostrar_informacion(self, detalles): # Muestra la información extraída del paquete DHCP.
        momento_actual = time.strftime("[%Y-%m-%d - %H:%M:%S]")
        info = (f"{momento_actual} : {detalles['mac_destino']} - "
                f"{detalles['nombre_host']}/{detalles['id_vendedor']} solicitó "
                f"{detalles['ip_solicitada']}")
        print(info)

if __name__ == "__main__":
    listener = DHCPListener()
    listener.iniciar_escucha()
