def ejemplo():
    x = 10
    y = 20
    z = x + y
    return z

# Convertir la función en bytecode
bytecode = ejemplo.__code__.co_code

'''
El atributo co_code contiene el bytecode de la función, que son las instrucciones de bajo nivel que la máquina virtual de Python (CPython)
usa para ejecutar el código.
'''
 
# Convertir cada byte a hexadecimal y formatearlo
hex_opcodes = ''.join(f"/x{byte:02x}" for byte in bytecode)

'''
Convierte cada byte del bytecode de la función en una cadena de texto lista para ser usada como shellcode (formato \x00\x1a\x...).

=> {byte:02x}: Toma el valor numérico del byte y lo convierte a su representación hexadecimal (x). El :02 asegura que siempre tenga dos dígitos, rellenando con un cero adelante si es necesario (ejemplo: 5 se convierte en 05).

=> f"\x...": Le antepone la cadena \x (que en Python representa un carácter hexadecimal literal) a ese número de dos dígitos.

''.join(...): Junta todas esas pequeñas cadenas (\x00, \x1a, etc.) en una única cadena grande.
'''

# Salida
print(f'[*] Salida común: {ejemplo()}\n[*] Salida en opcode: ') 
print(hex_opcodes)