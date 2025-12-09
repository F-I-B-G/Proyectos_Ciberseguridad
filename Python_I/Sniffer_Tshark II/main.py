from Sniffer_Tshark import SnifferTshark

if __name__ == '__main__':
    sniffer = SnifferTshark()

    print("""
    [1] Capturar en vivo
    [2] Leer archivo pcap
    """)
    opcion = input("Selecciona una opción: ")

    if opcion == "1":
        interface = input("Interfaz (por defecto 'any'): ") or "any"
        display_filter = input("Filtro de display (opcional): ") or ""
        sniffer.start_capture(interface, display_filter)

    elif opcion == "2":
        pcapfile = input("Ruta del archivo .pcap: ")
        display_filter = input("Filtro de display (opcional): ") or ""
        sniffer.read_capture(pcapfile, display_filter)
    else:
        print("[X] Opción no válida.")
        exit()

    print("""
    [1] Filtrar por protocolo
    [2] Filtrar por texto
    [3] Sin filtrar (usar todos)
    """)
    filtro_op = input("Selecciona una opción: ")

    if filtro_op == "1":
        protocolo = input("Protocolo: ")
        packets = sniffer.filter_by_protocol(protocolo)
    elif filtro_op == "2":
        text = input("Texto a buscar: ")
        packets = sniffer.filter_by_text(text)
    elif filtro_op == "3":
        packets = sniffer.capture_packets
    else:
        print("[X] Opción no válida.")
        exit()

    print(f"[+] Total paquetes seleccionados: {len(packets)}")

    exportar = input("¿Exportar a .pcap? (s/n): ").lower()
    if exportar == "s":
        filename = input("Nombre del archivo (default 'capture.pcap'): ") or "capture.pcap"
        sniffer.export_to_pcap(packets, filename)

    detalle = input("¿Mostrar detalles de los paquetes? (s/n): ").lower()
    if detalle == "s":
        sniffer.print_packet_detail(packets)
