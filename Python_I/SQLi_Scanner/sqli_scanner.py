from auth_session import AuthSession
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import streamlit as st

class SQLIScanner:
    # La sesión debe ser autenticada
    def __init__(self, session, payload_file):
        self.session = session
        # Como al payload nos lo van a pasar en forma de fichero, en el constructor hay que leer ese fichero. No se puede usar como un parámetro más
        self.payload_file = self.load_payloads(payload_file)
        # Lista de vulns
        self.vulnerabilidades = []

    '''
    El fichero de payload se sacará del repositorio en GitHub => https://github.com/payloadbox/xss-payload-list
    '''
    # Carga y lee el fichero con los payloads
    def load_payloads(self, filename):
        # 'filename' es el nombre de la ubicación del fichero
        try:
            with open(filename, 'r') as file:
                # Con un "List Comprehension" se va a procesar el .txt con los payloads para que cada uno sea un elemento de la lista
                return [line.strip() for line in file if line.strip() and not line.startswith('<!--')] # Saca los espacios y si esa línea no empieza con un comentario, la pone en la lista
        except IOError as e: # En caso de que salga un input/output error
            st.error(f'Error leyendo el archivo {filename}.\n El error que se produjo fue: {e}')
            return []
    
    def get_all_forms(self, url):
        # Se hace la petición a la URL que se quiere analizar
        response = self.session.get(url)
        # Se analiza y procesa
        soup = bs(response.content, 'html.parser')
        # Nos devuelve cada forms
        return soup.find_all('form')

    def get_form_details(self, form):
        # Devuelve un diccionario
        details = {
            'action': form.attrs.get('action', '').lower(),
            'method': form.attrs.get('method', '').lower(),
            'inputs': [{'type': input_tag.attrs.get('type', 'text'), 'name': input_tag.attrs.get('name')} for input_tag in form.find_all('input')]
        }
        return details

    def submit_form(self, form_details, url, value):
        target_url = urljoin(url, form_details['action'])
        # Se analiza dónde va cada info en el campo de login, se visualiza que van en la URL: http://192.168.146.143:8080/xss_get.php?firstname=test&lastname=test1&form=submit
        data = {input['name']: value if input['type'] in ['text', 'search'] else input.get('value', '')
                for input in form_details['inputs'] if input['name']}
        
        # Usando list comprehension, se crea en una sola línea un script que recorra cada input del formulario proporcionado siempre
        # que tengan un nombre asociado e inserto el payload en cada campo de entrada que haya. En este ejemplo en los campos name y lastname.

        # Se define el tipo de petición a realizar comprobando el method del form_details
        if form_details['method'] == 'post':
            data['form'] = 'submit'
            response = self.session.post(target_url, data=data)
        else:
            response = self.session.get(target_url, params=data)
        return response, response.url

    def is_vulnerable(self, response):
        # Si en la respuesta del servidor no aparece este mensaje es porque algo está pasando, ya sea que funcó el payload o mostró algo.
        if 'Invalid credentials!'.lower() in response.text.lower():
            return False # Página probablemente no vulnerable
        else:
            return True

    # Escanea en busca de XSS
    def sqli_scan(self, url):
        # Primero se identifican los componentes dentro de la página web que no sanitizan bien el input del usuario
        forms = self.get_all_forms(url)
        for form in forms:
            # Se obtienen los detalles
            for_details = self.get_form_details(form)
            progress_text = st.empty()
            for payload in self.payload_file:
                progress_text.text(f'Payload usado: {payload}')
                # Se va a obtener una respuesta y una URL con el payload cargado del XSS
                response, exploit_url = self.submit_form(for_details, url, payload)
                # Compruebo si el ataque fue efectivo
                if self.is_vulnerable(response): # Si retornó un True
                    # Compruebo que se inyectó el payload compelto
                    self.vulnerabilidades.append({
                        'payload': payload,
                        'url': url,
                        'exploit_url': exploit_url,
                        'form_details': for_details
                    })
        progress_text.empty()
    
    def display_results(self):
        if self.vulnerabilidades:
            st.success(f'Vulnerabilidades encontradas: {len(self.vulnerabilidades)}')
            for vulnerability in self.vulnerabilidades[:100]: # Debido a que se usa VPLE y está plagado de vulns, solo se mostrarán las primeras 100.
                st.markdown(f'**Payload**: `{vulnerability["payload"]}`')
                st.markdown(f'**URL**: `{vulnerability["url"]}`')
                st.markdown(f'**Exploit URL**: `{vulnerability["exploit_url"]}`')
                st.json(vulnerability['form_details'])
            else:
                st.error('No se han encontrado vulns.')

def main():
    # Título de la aplicación
    st.title('SQLi Scanner')
    base_url = st.text_input('URL base', 'http://192.168.146.143:8080')
    username = st.text_input('Username', 'usuario1')
    password = st.text_input('Password', '1234')
    security_level = st.selectbox('Security Level', [0, 1, 2], index=0) # Se establece desde la misma página de la aplicación vulnerable también. En este caso se creó un selector de nivel.
    payloads = 'sqli_payloads.txt'

    # Sesión autenticada
    session = AuthSession(base_url, username, password, security_level)
    xss_scanner = SQLIScanner(session, payloads)

    target_url = st.text_input('Target URL', 'http://192.168.146.143:8080/sqli_3.php')

    # Cuando el usuario pulse el botón de escanear
    if st.button('Scann SQLi'):
        # Se crea un botón de carga
        with st.spinner('En progreso...', show_time=True):
            xss_scanner.sqli_scan(target_url)
            xss_scanner.display_results()

if __name__ == '__main__':
    main()

# Ejecutar con: streamlit run sqli_scanner.py 