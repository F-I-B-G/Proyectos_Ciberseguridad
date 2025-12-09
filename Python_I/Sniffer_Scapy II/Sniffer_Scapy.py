import os
import sys
import socket
from datetime import datetime
from scapy.all import sniff, PcapReader, wrpcap, get_if_list
from colorama import Fore, Style, init

init(autoreset=True)

class SnifferScapyPro:
    def __init__(self):
        self.captured_packets = []

    def list_interfaces(self):
        interfaces = get_if_list()
        print(Fore.CYAN + "\n[+] Interfaces disponibles:")
        for idx, iface in enumerate(interfaces):
            print(f"   {idx+1}. {iface}")
        return interfaces

    def start_capture(self, interface='any', bpf_filter=''):
        print(Fore.GREEN + f"\n[+] Capturando en interfaz: {interface} | Filtro: '{bpf_filter}'")
        print(Fore.YELLOW + "[!] Pulsa CTRL + C para detener la captura.")
        try:
            self.captured_packets = sniff(
                iface=interface,
                filter=bpf_filter,
                prn=lambda pkt: print(Fore.BLUE + pkt.summary()),
                store=True
            )
        except KeyboardInterrupt:
            print(Fore.RED + f"\n[+] Captura finalizada. Paquetes capturados: {len(self.captured_packets)}")

    def read_capture(self, pcapfile):
        try:
            self.captured_packets = [pkt for pkt in PcapReader(pcapfile)]
            print(Fore.GREEN + f"[+] Lectura correcta del archivo: {pcapfile}")
        except Exception as e:
            print(Fore.RED + f"[x] Error al leer el pcap: {e}")

    def filter_protocol(self, protocol):
        try:
            from scapy.layers.inet import TCP, UDP, ICMP
            protocols_map = {"TCP": TCP, "UDP": UDP, "ICMP": ICMP}
            proto_layer = protocols_map.get(protocol.upper(), None)
            if not proto_layer:
                print(Fore.RED + "[x] Protocolo no soportado.")
                return []
            filtered = [pkt for pkt in self.captured_packets if pkt.haslayer(proto_layer)]
            print(Fore.CYAN + f"[+] Paquetes filtrados por {protocol}: {len(filtered)}")
            return filtered
        except Exception as e:
            print(Fore.RED + f"[x] Error filtrando por protocolo: {e}")
            return []

    def filter_by_text(self, text):
        filtered_packets = []
        for pkt in self.captured_packets:
            layer = pkt
            while layer:
                for field in layer.fields_desc:
                    if text.lower() in field.name.lower() or text.lower() in str(layer.getfieldval(field.name)).lower():
                        filtered_packets.append(pkt)
                        break
                layer = layer.payload
        print(Fore.CYAN + f"[+] Paquetes que contienen '{text}': {len(filtered_packets)}")
        return filtered_packets

    def print_packet_detail(self, packets=None):
        if packets is None:
            packets = self.captured_packets
        for packet in packets:
            packet.show()
            print(Fore.YELLOW + '---' * 20)

    def export_to_pcap(self, packets, filename='capture.pcap'):
        try:
            abs_path = os.path.abspath(filename)
            wrpcap(abs_path, packets)
            print(Fore.GREEN + f"[+] Paquetes guardados en: {abs_path}")
        except Exception as e:
            print(Fore.RED + f"[x] Error guardando el archivo: {e}")

def menu():
    sniffer = SnifferScapyPro()

    while True:
        print(Fore.MAGENTA + "\n=== Menú Sniffer Scapy Pro ===")
        print("1. Listar interfaces")
        print("2. Capturar tráfico")
        print("3. Leer archivo pcap")
        print("4. Filtrar por protocolo")
        print("5. Filtrar por texto")
        print("6. Mostrar detalles de paquetes")
        print("7. Exportar a pcap")
        print("8. Salir")

        option = input(Fore.YELLOW + "\nElige una opción: ")

        if option == '1':
            sniffer.list_interfaces()

        elif option == '2':
            interfaces = sniffer.list_interfaces()
            idx = int(input("Selecciona interfaz (número): ")) - 1
            iface = interfaces[idx] if 0 <= idx < len(interfaces) else 'any'
            bpf = input("Filtro BPF (vacío para ninguno): ")
            sniffer.start_capture(interface=iface, bpf_filter=bpf)

        elif option == '3':
            file = input("Ruta del pcap: ")
            sniffer.read_capture(file)

        elif option == '4':
            proto = input("Protocolo (TCP/UDP/ICMP): ")
            filtered = sniffer.filter_protocol(proto)
            sniffer.print_packet_detail(filtered)

        elif option == '5':
            text = input("Texto a buscar: ")
            filtered = sniffer.filter_by_text(text)
            sniffer.print_packet_detail(filtered)

        elif option == '6':
            sniffer.print_packet_detail()

        elif option == '7':
            filename = input("Nombre del archivo pcap (default: capture.pcap): ") or "capture.pcap"
            sniffer.export_to_pcap(sniffer.captured_packets, filename)

        elif option == '8':
            print(Fore.GREEN + "[+] Saliendo...")
            sys.exit()

        else:
            print(Fore.RED + "[x] Opción no válida.")

if __name__ == "__main__":
    menu()
