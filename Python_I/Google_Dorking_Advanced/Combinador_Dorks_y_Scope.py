from pathlib import Path

# Rutas a los archivos originales
scope_file = Path("/mnt/data/Scope_Inzpire.txt")
dorks_file = Path("/mnt/data/Dorking.txt")

# Leer contenido
scopes = [line.strip() for line in scope_file.read_text(encoding="utf-8").splitlines() if line.strip()]
dorks = [line.strip() for line in dorks_file.read_text(encoding="utf-8").splitlines() if line.strip()]

# Lista para combinaciones
combined_queries = []

for scope in scopes:
    # Limpiar "https://" o "/" si lo hubiera, para usarlo en site:
    clean_scope = scope.replace("https://", "").replace("http://", "").strip("/")
    # Si es IP CIDR o IP normal, no usar site:, usar tal cual
    if any(c.isalpha() for c in clean_scope):
        # Es dominio
        for dork in dorks:
            combined_queries.append(f"site:{clean_scope} {dork}")
    else:
        # Es IP o rango
        for dork in dorks:
            combined_queries.append(f"{clean_scope} {dork}")

# Guardar nuevo archivo de combinaciones
output_file = Path("/mnt/data/Dorks_Combinados_Inzpire.txt")
output_file.write_text("\n".join(combined_queries), encoding="utf-8")

output_file, len(combined_queries)
