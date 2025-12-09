import pyzipper
import argparse
import logging
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ZipCracker:
    # Tanto en Linux como en WIndows, usan AES para encriptar por defecto.
    def __init__(self, ruta_archivo_zip):
        try:
            self.archivo_zip = pyzipper.AESZipFile(ruta_archivo_zip)
        except FileNotFoundError:
            logging.error(f'[!] El archivo {ruta_archivo_zip} no existe.')
            raise
        except pyzipper.BadZipFile:
            logging.error(f'[!] El archivo {ruta_archivo_zip} no es un Zip válido.')
            raise
    
    def crack_zip(self, wordlist):
        try:
            with open(wordlist, 'rb') as archivo: # 'latin-1' => encode para trabajar bien con rockyou
                passwords = archivo.readlines()
        except FileNotFoundError:
            logging.error(f'[!] El archivo \'{wordlist}\' no existe.')
            raise
        except Exception as e:
            logging.error(f'[!] Se produjo un error al leer \'{wordlist}\'.\nError:{str({e})}')
            raise

        logging.info(f'[*] Intentando descifrar el archivo Zip con una lista de {len(passwords)} passwords.')
        for password in tqdm(passwords, desc='Descifrando Zip', unit='password'):
            try:
                self.archivo_zip.pwd = password.strip()
                self.archivo_zip.extractall()
            except (RuntimeError, pyzipper.BadZipFile, pyzipper.LargeZipFile) as e:
                logging.error(f'[!] Fallo con {password.strip().decode()}: {e}')
                continue # Así no para y continúa con la siguiente contraseña
            else:
                password = password.decode().strip()
                return password
        return None

def main():
    parser = argparse.ArgumentParser(description="Descifra un fichero comprimido .ZIP")
    parser.add_argument("zipfile", help='La ruta al archivo .ZIP')
    parser.add_argument("wordlist", help='La ruta al diccionario de contraseñas.')
    args = parser.parse_args()

    cracker = ZipCracker(args.zipfile)

    resultado = cracker.crack_zip(args.wordlist)

    if resultado:
        logging.info(f"[+] Contraseña encontrada: {resultado}")
    else:
        logging.info("[-] No se encontraron coincidencias.")

if __name__ == '__main__':
    main()

# Modo de ejecución: python cracking_zip.py /home/kali/Desktop/archivo_secreto.zip /usr/share/wordlists/rockyou.txt