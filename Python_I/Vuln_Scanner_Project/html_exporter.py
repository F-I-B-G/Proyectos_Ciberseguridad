# html_exporter.py
from jinja2 import Environment, FileSystemLoader
import os

def export_html(cves_data, service_name="Servicios", output_path="reporte.html"):
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    # Si templates no está en el mismo nivel, fallback a ./templates
    if not os.path.isdir(templates_dir):
        templates_dir = os.path.join(os.getcwd(), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("reporte.html")
    html = template.render(service=service_name, cves=cves_data)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Reporte exportado en {output_path}")
