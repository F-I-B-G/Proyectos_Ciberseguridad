from Metadatos_Python import extract_metadata

if __name__ == '__main__':
    # Ruta a un fichero.
    filepath = input('Ingresa la ruta del archivo: ')
    metadata = extract_metadata(filepath)
    # Obtenemos el diccionario:
    for key, value in metadata.items():
        print(f'{key}: {value}')