# results_parser.py
"""
ResultsProcessor:
- Mostrar en consola con rich (tabla)
- Exportar a json / html / csv
- Dedupe de resultados
- Añadir metadata (timestamp, query si viene)
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
import html
import os

class ResultsProcessor:
    def __init__(self, resultados, metadata=None):
        """
        resultados: lista de dict con keys 'title','description','link'
        metadata: dict opcional (p.ej {'query': '...'})
        """
        self.resultados = self._dedupe(resultados)
        self.metadata = metadata or {}

    def _dedupe(self, results):
        seen = set()
        out = []
        for r in results:
            link = r.get("link")
            if link and link not in seen:
                seen.add(link)
                out.append(r)
        return out

    def mostrar_pantalla(self):
        console = Console()
        table = Table(show_header=True, header_style="bold green")
        table.add_column("#", style="dim", width=4)
        table.add_column("Titulo", width=50)
        table.add_column("Descripcion", width=60)
        table.add_column("Enlace", overflow="fold")

        for idx, r in enumerate(self.resultados, 1):
            title = r.get("title", "")
            desc = r.get("description", "")
            link = r.get("link", "")
            table.add_row(str(idx), title, desc, link)
        console.print(table)

    def exportar_json(self, archivo_salida=None):
        out = {
            "metadata": self.metadata,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "results": self.resultados
        }
        archivo_salida = archivo_salida or f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        Path(archivo_salida).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] JSON guardado en {os.path.abspath(archivo_salida)}")

    def exportar_csv(self, archivo_salida=None):
        archivo_salida = archivo_salida or f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(archivo_salida, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["index", "title", "description", "link"])
            for idx, r in enumerate(self.resultados, 1):
                writer.writerow([idx, r.get("title",""), r.get("description",""), r.get("link","")])
        print(f"[+] CSV guardado en {os.path.abspath(archivo_salida)}")

    def exportar_html(self, archivo_salida="report.html", html_template_path="html_template.html"):
        # Leer plantilla
        if not os.path.exists(html_template_path):
            # Si falta plantilla, hacemos un HTML simple
            items_html = ""
            for i, r in enumerate(self.resultados, 1):
                items_html += f"<div class='resultado'><h3>{html.escape(r.get('title',''))}</h3><p>{html.escape(r.get('description',''))}</p><a href='{html.escape(r.get('link',''))}'>{html.escape(r.get('link',''))}</a></div>\n"
            content = f"<html><body><h1>Report</h1>{items_html}</body></html>"
            Path(archivo_salida).write_text(content, encoding="utf-8")
            print(f"[+] HTML simple guardado en {os.path.abspath(archivo_salida)}")
            return

        plantilla = Path(html_template_path).read_text(encoding="utf-8")
        elementos_html = ""
        for idx, r in enumerate(self.resultados, 1):
            t = html.escape(r.get("title",""))
            d = html.escape(r.get("description",""))
            l = html.escape(r.get("link",""))
            elemento = f"""
            <div class="resultado">
              <div class="indice">Resultado {idx}</div>
              <h5>{t}</h5>
              <p>{d}</p>
              <a href="{l}" target="_blank">{l}</a>
            </div>
            """
            elementos_html += elemento
        informe_html = plantilla.replace('{{ resultados }}', elementos_html)
        Path(archivo_salida).write_text(informe_html, encoding="utf-8")
        print(f"[+] HTML guardado en {os.path.abspath(archivo_salida)}")
