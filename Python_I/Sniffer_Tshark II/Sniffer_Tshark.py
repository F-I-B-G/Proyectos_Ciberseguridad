import os
import pyshark
from scapy.all import wrpcap, Ether


class SnifferTshark:
    def __init__(self):
        self.capture = None
        self.capture_packets = []

    # Captura en vivo
    def start_capture(self, interface='any', display_filter=''):
        self.capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter,
            use_json=True,
            include_raw=True
        )
        try:
            print('[+] Capturando paquetes... (CTRL + C para detener)')
            for packet in self.capture.sniff_continuously():
                self.capture_packets.append(packet)
        except (KeyboardInterrupt, EOFError):
            print(f'[!] Captura detenida. Total: {len(self.capture_packets)} paquetes.')

    # Filtrar por protocolo
    def filter_by_protocol(self, protocolo):
        filtered_packets = [pkt for pkt in self.capture_packets if protocolo in pkt]
        return filtered_packets

    # Leer archivo pcap
    def read_capture(self, pcapfile, display_filter=''):
        try:
            self.capture = pyshark.FileCapture(
                input_file=pcapfile,
                display_filter=display_filter,
                keep_packets=False,
                use_json=True,
                include_raw=True
            )
            self.capture_packets = [pkt for pkt in self.capture]
            print(f'[+] Lectura de "{pcapfile}" completada. Total: {len(self.capture_packets)} paquetes.')
        except Exception as e:
            print(f'[X] Error leyendo {pcapfile}: {e}')

    # Filtrar por texto en el contenido
    def filter_by_text(self, text):
        filtered_packets = []
        for pkt in self.capture_packets:
            for layer in pkt.layers:
                for field_line in layer._get_all_field_lines():
                    if text.lower() in str(field_line).lower():
                        filtered_packets.append(pkt)
                        break
        return filtered_packets

    # Exportar a pcap mostrando ruta absoluta
    def export_to_pcap(self, packets, filename='capture.pcap'):
        try:
            scapy_packets = [Ether(pkt.get_raw_packet()) for pkt in packets]
            wrpcap(filename, scapy_packets)
            abs_path = os.path.abspath(filename)
            print(f'[+] Paquetes guardados como: {abs_path}')
        except Exception as e:
            print(f'[X] Error exportando: {e}')

    # Imprimir detalles
    def print_packet_detail(self, packets=None):
        if packets is None:
            packets = self.capture_packets
        for packet in packets:
            print(packet)
            print('---' * 20)
