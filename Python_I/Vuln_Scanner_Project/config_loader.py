# config_loader.py
def load_config(path="config.txt"):
    config = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except FileNotFoundError:
        raise FileNotFoundError("No se encontró config.txt. Creá uno en la carpeta del script.")
    return config
