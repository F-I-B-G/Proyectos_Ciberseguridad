'''
Docstring para Extras.Desamblar_EXE

1 - pip install capstone
2 - Tener un exe
'''

from capstone import *
 
# Leer el contenido binario del archivo .exe
with open("ruta/a/tu/archivo.exe", "rb") as f:
    codigo_binario = f.read()
 
# Crear una instancia de Capstone para desensamblar el código binario
md = Cs(CS_ARCH_X86, CS_MODE_64)  # Asumiendo que estás trabajando con archivos x64
 
# Desensamblar el código binario y solo imprimir los opcodes
for i in md.disasm(codigo_binario, 0x1000):  # Suponiendo que el código comienza en el offset 0x1000
    # Generar y imprimir la cadena de opcodes en el formato especificado
    print(''.join(['\\x{:02x}'.format(x) for x in i.bytes]))
