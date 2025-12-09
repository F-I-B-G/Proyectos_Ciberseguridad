import requests
import tempfile
import webbrowser
import time
import os

class AuthSession:
    # Se va a crear una sesión web autenticada
    def __init__(self, base_url, username, password, security_level=0):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.security_level = security_level
        self.session = requests.Session() # Crea la sesión
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',  # Agente que hace la petición
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',  # Tipos de contenido aceptados
            'Accept-Language': 'es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3',  # Idiomas preferidos
            'Accept-Encoding': 'gzip, deflate, br',  # Compresiones aceptadas
            'Content-Type': 'application/x-www-form-urlencoded',  # Tipo de cuerpo enviado
            # 'Content-Length': '57',  # Longitud del cuerpo (normalmente lo calcula la librería)
            'Origin': f'{self.base_url}',  # Origen de la petición
            # 'Sec-GPC': '1',  # Global Privacy Control
            'Connection': 'keep-alive',  # Mantener conexión persistente
            'Referer': f'{self.base_url}/login.php',  # Página desde la que se hace la petición
            # 'Cookie': 'PHPSESSID=eg7j77t6egof5ghase109v37j3; security_level=0',  # Sesión y nivel de seguridad
            'Upgrade-Insecure-Requests': '1',  # Solicita pasar a HTTPS si está disponible
            # 'Priority': 'u=0, i'  # Prioridad de la petición
        } # Cabeceras para autenticación. ej => user_agent, accept,accept-language
        # Creamos una sesión autenticada
        self.login()
    
    def login(self):
        # Datos a enviar en una petición POST
        login_data = {
            'login': self.username,
            'password': self.password,
            'security_level': self.security_level,
            'form': 'submit'
        }

        response = self.session.post(f'{self.base_url}/login.php', headers=self.headers, data=login_data) # Lo que se va a postear
        
        # Para corroborar si se autenticó con éxito, una forma es verificar si en la página de login, aparece un mensaje del estilo "welcome user1"
        if f'Welcome {self.username}'.lower() in response.text.lower():
            print('[+] Autenticación exitosa.')
            return response # Se retorna el contenido de la página autenticada
        else:
            print('[!] Error en la autenticación. \nCódigo del estado de la respuesta: ', response.status_code)
            return response # Para saber el por qué
        
    
    # Se comprueba si estamos autenticados
    def get(self, target_url, **kwargs): # **kwargs es para pasarle parámetros por referencia y así no especificar cada uno
        # Obtenemos la página
        return self.session.get(target_url, headers=self.headers, **kwargs)

    def post(self, target_url, data):
        return self.session.post(target_url, headers=self.headers, data=data)

if __name__ == '__main__':
    base_url = input('Ingrese la URL BASE o presione ENTER para usar la predeterminada: ') or 'http://192.168.146.143:8080' # Debido a que Python no tiene una forma de agregar un valor por defecto al input, esta es una manera de hacerlo
    username = 'usuario1'
    password = '1234'
    auth_session = AuthSession(base_url, username, password)

    # Especificar la URL que se quiere acceder de manera autenticada
    target_url = input('Ingrese la URL OBJETIVO o presione ENTER para usar la predeterminada: ') or 'http://192.168.146.143:8080/xss_get.php'
    response = auth_session.get(target_url)

    # Mostrar la página web obtenida
    '''
    Primero se escribe en disco como un archivo temporal y luego se abrirá en un navegador.
    Para eso se usará la librería "tempfile"
    '''

    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as file: # En Linux se guarda en la carpeta "tmp". Si se pone 'delete=True, una vez que se trabajó con el with, se elimina; importante para tener en cuenta.
        file.write(response.content.decode('utf-8'))
        temp_html_path = file.name
    
    # Para visualizar el fichero se hace uso de la librería 'webbrowser'
    webbrowser.open(f'file://{temp_html_path}') # El 'file://' es para buscar un fichero dentro de nuestro PC

    # Una vez se abrió el fichero y se analizó, se elimina cuando el usuario presiona CTRL + C
    try:
        print('[*] Pulsa CTRL + C para cerrar el programa y eliminar el fichero temporal.')
        time.sleep(999999)
    except KeyboardInterrupt:
        os.unlink(temp_html_path) # Se elimina el fichero temporal
        print(f'[+] Archivo temporal "{temp_html_path}" eliminado')