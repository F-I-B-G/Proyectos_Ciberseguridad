# Para trabajar con la tool, hay que consultar con la API dentro de la misma tool: tools/options/API/API KEY
# Hay que tener la herramienta abierta cuando se ejecute el código

from zapv2 import ZAPv2
from dotenv import load_dotenv
import os
import time
import streamlit as st
from collections import defaultdict
from urllib.parse import urlparse

class ZapAnalyzer():
    # Escala de riesgo a definir
    RISK_MAPPING = {
        'Informational': 0,
        'Low': 1,
        'Medium': 2,
        'High': 3
    }

    def __init__(self, target_url):
        '''
        Primero se va a implementar un proceso de spidering con Zap, luego un análisis pasivo y activo.
        '''
        # Se carga la variable de entorno con la API
        load_dotenv()
        api_key = os.getenv('ZAP_API_KEY') # La variable que está en el archivo .env
        if not api_key:
            # Si no se encontró una API o no se pudo leer, se emite una excepción
            raise ValueError('[!] API KEY no encontrada.\n Asegurate de incluir la API KEY en el .env')
        self.target_url = target_url
        # Se inicia el cliente ZAP
        self.zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    def start_spider(self):
        scan_id = self.zap.spider.scan(self.target_url)
        # Se mostrará el porcentaje de avance del escaneo
        while int(self.zap.spider.status(scan_id)) < 100:
            # print(self.zap.spider.status(scan_id)) - forma 1
            time.sleep(2)
        return self.zap.spider.results()

    # Se realizará un escaneo pasivo
    def passive_scan(self):
        self.zap.pscan.enable_all_scanners()
        self.zap.urlopen(self.target_url)
        # Mientras haya URLs sin escanear, el proceso va a continuar
        while int(self.zap.pscan.records_to_scan) > 0:
            time.sleep(2)
        return self.zap.core.alerts()

    def active_scan(self):
        '''
        Se recomienda hacer esto para analizar todas las páginas, almacena las URLs en el cliente Zap y
        cuando se lance el escaneo activo, las usará.
        '''
        self.start_spider()
        scan_id = self.zap.ascan.scan(self.target_url)
        while int(self.zap.ascan.status(scan_id)) > 100:
            time.sleep(2)
        return self.zap.core.alerts()


    # Se mostrarán los resultados obtenidos
    def display_results(self):
        # Título de la aplicación que se va a crear
        st.title('Web Spidering and Passive/Active Scan Tool')
        # El usuario va a seleccionar si hacer un passive scan o spidering
        operation = st.radio('Selecciona la operación', ('Spidering', 'Passive Scan', 'Active Scan')) # El usuario va a seleccionar una de las dos opciones y dicho valor será añadido a la variable

        # Si se activa el botón
        if st.button('Start Process'):
            try:
                if operation == 'Spidering':
                    results = self.start_spider()
                    st.success('[+] Spidering finalizado exitosamente.')
                    self._display_urls(results)
                elif operation == 'Passive Scan':
                    results = self.passive_scan()
                    st.success('[+] Escaneo pasivo finalizado exitosamente.')
                    self._display_alerts(results)
                elif operation == 'Active Scan':
                    results = self.active_scan()
                    st.success('[+] Escaneo activo finalizado exitosamente.')
                    self._display_alerts(results)
            except Exception as e:
                st.error(f'Error: {str(e)}')

    def _display_urls(self, results):
        '''
        Se va a crear un diccionario para que al inicializar con una key nueva, va a tener un valor
        por defecto asociado que será una lista.
        '''
        organized_results = defaultdict(list)

        # Voy a recorrer todas las URLs obtenidas en el proceso de spidering
        for url in results:
            # Se analiza la URL y se parsea para poder trabajar
            parsed_url = urlparse(url)
            # Se accede a la ruta
            path = parsed_url.path
            # Si la ruta no termina con una barra, quiere decir que es un archivo y me va a interesar
            # el directorio anterior a ese archivo para organizar las direcciones
            if not path.endswith('/'):
                # Se van a unir elementos de la lista separados por la barra.
                # La lista estará conformada por elementos que se dividen por la barra y se va a descartar
                # el último que sería el archivo.
                # Básicamente, agarra la ruta entera incluido el archivo, la disecciona en una lista,
                # elimina lo último que sería el archivo y vuelve a unir toda la ruta usando la barra como separador.   
                path = '/'.join(path.split('/')[:-1])
            organized_results[path].append(url)

            # Mostrar resultados organizados
            for path, urls in sorted(organized_results.items()):
                # Se irán creando entradas en la aplicación web
                st.subheader(path)  # Título de la cabecera
                for url in sorted(urls):
                    st.write(f'[{url}]({url})')
    
    def _display_alerts(self, alerts):
        # Se van a ordenar según el grado de criticidad. Se recorrerá cada una y según su riesgo, se irán ordenando
        alerts_sorted = sorted(alerts, key=lambda x: self.RISK_MAPPING.get(x['risk'], -1), reverse=True)
        for alert in alerts_sorted:
            st.write(f"**{alert['alert']}** - {alert['risk']} Risk")
            st.write(f"URL: {alert['url']}")
            st.write(f"Description: {alert['description']}")
            st.write(f"Solution: {alert['solution']}")


if __name__ == '__main__':
    target_url = st.text_input('[*] Introduce la URL: ', 'http://192.168.146.143:8899/a3.html') # La URL por defecto es la del entorno vulnerable VPLE
    analyzer = ZapAnalyzer(target_url)
    analyzer.display_results()

'''
# --------------------------------------------------------------------------------- #
# Para ejecutar el script desde la CLI: streamlit run RUTA_DEL_SCRIPT [ARGUMENTOS]  #
#                                                                                   #
# Si se ejecuta desde la misma carpeta: streamlit run zap_analyzer.py [ARGUMENTS]   #
#                                                                                   #
# A veces Zap al realizar un escaneo activo no identifica todas las vulns.          #
# Se recomienda volverlo a ejecutar.                                                #
# --------------------------------------------------------------------------------- #
'''
