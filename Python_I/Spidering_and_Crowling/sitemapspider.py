import scrapy
import networkx as nx
from urllib.parse import urljoin
from pyvis.network import Network

# Clase que va a heredar usar los ficheros de scrapy
class SiteMapSpider(scrapy.Spider):
    name = 'sitemapper' # Nombre del proyecto
    # Dominios para analizar y no se vaya por las ramas
    allowed_domains = ['192.168.146.143'] # Atributo de clase que usará scrapy. En este caso solo buscará en direcciones vinculadas a esta dirección.
    start_urls = ['http://192.168.146.143:8899/a1.html'] # URLs por donde scrapy empezará a analizar

    def __init__(self):
        # Se va a inicializar el constructor de una clase padre en base al objeto principal
        super().__init__()
        self.tree = nx.DiGraph() # Se va a crear un árbol para despúes construir un diagrama con todas las URLs y su relación
    
    # Métodos necesarios para que Scrapy funcione:
    def parse(self, response):
        # 'response' corresponde a la respuesta de la petición que hizo scrapy a las urls de 'start_urls'
        current_url = response.url
        # Ahora esa url será agregada al árbol como un nodo
        self.tree.add_node(current_url, title=response.css('title::text').get())

        # Luego comienzo a analizar el contenido en busca de referencias a apartados de la misma aplicación web
        for href in response.css('a::attr(href)').getall():
            # Para cada enlace que encuentre dentro del dominio de la aplicación web, construimos la url completa.
            # Esto se debe a que como solo buscamos determinados apartados, hay que construir el enlace entero.
            full_url = urljoin(current_url, href)
            # Se añade la arista al nodo y se comprueba que no se haya añadido previamente
            if not self.tree.has_edge(current_url, full_url): # Comprueba justamente que no esté añadida
                self.tree.add_edge(current_url, full_url) # La añade en caso de que no esté
                yield scrapy.Request(full_url, callback=self.parse) # Hago la petición de nuevo para que comience todo el proceso nuevamente y vaya iterando contenido
            
    def close(self, reason):
        # 'reason' es la razón por la que termina el spidering
        self.draw_interactive_graph(self.tree) # Mostrará por pantalla el gráfico que se fue construyendo
    
    def draw_interactive_graph(self, graph):
        # Se va a decorar el gráfico
        net = Network(height='750px', width='100%', bgcolor='#222222', font_color='white', directed=True) # 'Directed' es para decir que el gráfico será dirigido, o sea, que se muestren las flechas.
        net.from_nx(graph)

        # Se van a configurar las físicas
        net.repulsion(node_distance=200, central_gravity=0.3, spring_length=200, spring_strength=0.05, damping=0.09)

        # -opcional- Desactivar las físicas 
        net.toggle_physics(True) # Inicia las físicas

        for node in graph.nodes:
            node_url = node
            html_link = f"<a href='{node_url}' target='_blank'>{node_url}</a>"
            net.get_node(node)['title'] = html_link
        
        # Guardar y mostrar el gráfico
        net.show('sitemap.html', notebook=False) 

'''
Para ejecutar el script, hay que ir a la carpeta "sitemapper" y ejecutar: scrapy crawl sitemapper
'''