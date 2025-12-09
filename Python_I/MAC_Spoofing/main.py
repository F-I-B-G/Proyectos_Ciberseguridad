from mac_spoofing import MACSpoofing

def main():
    """
    Función principal que maneja la lógica del programa para cambiar y restaurar
    direcciones MAC de una interfaz de red.

    Solicita al usuario la interfaz de red y la acción a realizar, luego ejecuta
    la acción correspondiente.
    """
    # Solicita al usuario que introduzca la interfaz de red
    interface = input("[*] Introduce la interfaz de red: ")
    mac_spoofer = MACSpoofing(interface)

    # Lee la dirección MAC original desde un archivo o desde la interfaz
    original_mac = mac_spoofer.read_mac_from_file() or mac_spoofer.get_current_mac()

    # Si no se ha leído una MAC desde el archivo, se guarda la MAC actual
    if not mac_spoofer.read_mac_from_file():
        mac_spoofer.write_mac_to_file(original_mac)

    print(f"[+] La dirección MAC actual es: {original_mac}")
    
    # Solicita al usuario que elija una opción
    action = input("[*] Elige una opción: [c] Cambiar MAC, [r] Restaurar MAC original, [s] Salir: ")

    if action.lower() == 'c':
        # Solicita al usuario la nueva dirección MAC
        new_mac = input("[*] Introduce la nueva dirección MAC (o escribe 'aleatoria' para generar una): ")
        if new_mac.lower() == 'aleatoria':
            new_mac = mac_spoofer.generate_random_mac()
        
        # Valida y cambia la dirección MAC
        if mac_spoofer.validate_mac(new_mac):
            mac_spoofer.change_mac(new_mac)
            updated_mac = mac_spoofer.get_current_mac()
            if updated_mac == new_mac:
                print(f"[+] La dirección MAC fue cambiada exitosamente a {updated_mac}")
            else:
                print("[!] Error al intentar cambiar la dirección MAC.")
        else:
            print("[!] El formato de la dirección MAC proporcionada no es correcto.")
    elif action.lower() == 'r':
        # Restaura la dirección MAC original
        mac_spoofer.change_mac(original_mac)
        if mac_spoofer.get_current_mac() == original_mac:
            print("[+] La dirección MAC original ha sido restaurada exitosamente.")
        else:
            print("[!] Error al restaurar la dirección MAC original.")
    elif action.lower() == 's':
        print("Saliendo del programa")
        return
    
if __name__ == "__main__":
    main()
