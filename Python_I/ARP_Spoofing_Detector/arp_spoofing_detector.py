from scapy.all import ARP, Ether, srp, sniff
import logging # Módulo para sacar por pantalla información

class ARPSpoofingDetector:
    def __init__(self):
        # Se va a configurar el logging para mostrar alertas por pantalla
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    def obtener_mac(self, ip):
        paquete = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        # Se envía el paquete
        resultado = srp(paquete, timeout=3, verbose=False)[0]
        try:
            return resultado[0][1].hwsrc # Si salió todo bien, obtener el primer valor (0) de la capa arp (1)
        except IndexError:
            raise IndexError('No se pudo obtener la dirección MAC para la IP proporcionada')
    
    def procesar_paquete(self, paquete):
        if paquete.haslayer(ARP) and paquete[ARP].op == 2:
            try:
                mac_real = self.obtener_mac(paquete[ARP].psrc)
                mac_respuesta = paquete[ARP].hwsrc
                if mac_real != mac_respuesta:
                    logging.warning(f'[¡ALERTA!] Hay un ataque ARP Spoofing. MAC REAL {mac_real} - MAC TRUCHA {mac_respuesta}')
            except IndexError:
                logging.error('Error al intentar obtener la MAC real debido a una posible IP falsa o problemas de red')
    
    def iniciar_deteccion(self):
        # Cuando vayan llegando los paquetes, se irán procesando
        sniff(store=False, prn=self.procesar_paquete)
    
if __name__ == '__main__':
    detector = ARPSpoofingDetector()
    detector.iniciar_deteccion()
