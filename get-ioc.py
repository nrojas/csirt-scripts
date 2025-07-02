import os
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Cargar variables desde .env
load_dotenv()
usuario = os.getenv("API_USER")
clave = os.getenv("API_PASS")
url_login = "https://apimisp.csirt.gob.cl/token"

# Token global en memoria
global_token = {
    "token": None,
    "timestamp": None
}
TOKEN_TTL = 30 * 60  # 30 minutos

def generar_rango_dia_actual():
    hoy = datetime.now().date()
    desde = datetime.combine(hoy, datetime.min.time())
    hasta = datetime.combine(hoy, datetime.max.time()).replace(microsecond=0)

    formato = "%Y-%m-%d %H:%M:%S"
    return desde.strftime(formato), hasta.strftime(formato)

def obtener_token():
    global global_token

    # Si el token es válido en memoria, reutilizarlo
    if global_token["token"] and global_token["timestamp"]:
        tiempo_actual = datetime.now().timestamp()
        if tiempo_actual - global_token["timestamp"] < TOKEN_TTL:
            return global_token["token"]
        else:
            print("🔁 Token expirado, solicitando uno nuevo...")

    # Autenticación
    credenciales = {
        "username": usuario,
        "password": clave
    }

    try:
        respuesta = requests.post(url_login, json=credenciales)
        respuesta.raise_for_status()
        json_resp = respuesta.json()
        token = json_resp.get("access_token") or json_resp.get("token")

        if token:
            global_token["token"] = token
            global_token["timestamp"] = datetime.now().timestamp()
            return token
        else:
            print("⚠️ Token no encontrado en respuesta:", json_resp)

    except requests.exceptions.RequestException as e:
        print("❌ Error al obtener token:", e)

    return None

def guardar_resultado(datos_json, nombre_base="resultado"):
    carpeta = Path("resultados")
    carpeta.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nombre_archivo = carpeta / f"{nombre_base}_{timestamp}.json"

    with open(nombre_archivo, "w", encoding="utf-8") as f:
        json.dump(datos_json, f, ensure_ascii=False, indent=2)

    print(f"📝 Resultado guardado en: {nombre_archivo}")

def consultar_ioc(nombre: str, url: str):
    token = obtener_token()
    if not token:
        print(f"❌ No se pudo autenticar para {nombre}.")
        return

    fecha_desde_str, fecha_hasta_str = generar_rango_dia_actual()

    solicitud = {
        "fecha_desde": fecha_desde_str,
        "fecha_hasta": fecha_hasta_str
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        respuesta = requests.post(url, json=solicitud, headers=headers)
        respuesta.raise_for_status()

        datos = respuesta.json()
        print(f"✅ Resultados de {nombre.replace('_', ' ').title()}:")
        print(datos)
        guardar_resultado(datos, nombre_base=nombre)

    except requests.exceptions.HTTPError as e:
        print(f"❌ Error HTTP al consultar {nombre}: {e}")
        print("Código:", respuesta.status_code)
        print("Respuesta:", respuesta.text)

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de conexión al consultar {nombre}: {e}")


def main():
    print("CSIRT Chile - Obtención de indicadores de compromiso")
    print("-----------------------------------------------------")
    print("Procesando: Direcciones IP sospechosas de las últimas 24 horas...")
    consultar_ioc("ioc_ips", "https://apimisp.csirt.gob.cl/ioc/ip_amenazas")
    print("Procesando: Dominios sospechosos de las últimas 24 horas...")
    consultar_ioc("ioc_dominios", "https://apimisp.csirt.gob.cl/ioc/dominios")
    print("Procesando: URLs sospechosas de las últimas 24 horas...")
    consultar_ioc("ioc_urls", "https://apimisp.csirt.gob.cl/ioc/urls")
    print("Procesando: Hashes IOC sospechosos de las últimas 24 horas...")
    consultar_ioc("ioc_hashes", "https://apimisp.csirt.gob.cl/ioc/hashes")
    print("Procesando: Archivos sospechosos de las últimas 24 horas...")
    consultar_ioc("ioc_archivos", "https://apimisp.csirt.gob.cl/ioc/archivos")
    print("Procesando: Direcciones de correo sospechosas de las últimas 24 horas...")
    consultar_ioc("ioc_correos", "https://apimisp.csirt.gob.cl/ioc/correos_phishing")    

if __name__ == "__main__":
    main()