# Requiere las librerías requests y dotenv.

import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Obtener el usuario y contraseña de autenticación para la API desde un archivo .env
usuario = os.getenv("API_USER")
clave = os.getenv("API_PASS")

# URL de Autorización del CSIRT (Para obtener el Bearer Token).
url_login = "https://apimisp.csirt.gob.cl/token"




credenciales = {
    "username": usuario,
    "password": clave
}

# Intentar obtener el Bearer Token.
try:
    # Hacer la solicitud POST
    respuesta = requests.post(url_login, json=credenciales)
    respuesta.raise_for_status()  # Lanza error si status_code no es 200-299

    # Obtener el token desde la respuesta
    json_resp = respuesta.json()
    token = json_resp.get("access_token") or json_resp.get("token")

    if token:
        print("✅ Token Bearer obtenido:")
        print(token)
    else:
        print("⚠️ No se encontró el token en la respuesta.")
        print("Respuesta completa:", json_resp)

except requests.exceptions.HTTPError as e:
    print(f"❌ Error HTTP: {e}")
    print("Código de estado:", respuesta.status_code)
    print("Contenido:", respuesta.text)

except requests.exceptions.RequestException as e:
    print(f"❌ Error de conexión: {e}")

except Exception as e:
    print(f"❌ Error inesperado: {e}")
