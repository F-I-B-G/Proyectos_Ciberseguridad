from netfilterqueue import NetfilterQueue
from scapy.all import *

def intercept(packet): # Función que procesa paquetes
    payload = packet.get_payload()
    spkt = IP(payload)
    spkt.show() # Método para visualizar el paquete
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
