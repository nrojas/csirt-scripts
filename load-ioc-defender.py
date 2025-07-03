import os
import json
import requests
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import load_dotenv
import argparse
import re
from urllib.parse import urlparse

# ========================== CONFIG =============================
TIPOS_IOC_DEFENDER = {
    "ioc_ips":      {"tipo": "IpAddress",    "ttl_dias": 15},
    "ioc_dominios": {"tipo": "DomainName",   "ttl_dias": 15},
    "ioc_urls":     {"tipo": "Url",          "ttl_dias": 7},
    "ioc_hashes":   {"tipo": "FileSha256",   "ttl_dias": 180},
    "ioc_correos":  {"tipo": "EmailAddress", "ttl_dias": 30},
    "ioc_archivos": {"tipo": "FileName",     "ttl_dias": 180}
}

# ========================== AUTENTICACION =============================
load_dotenv()
TENANT_ID = os.getenv("ENTRA_TENANTID")
CLIENT_ID = os.getenv("ENTRA_CLIENTID")
CLIENT_SECRET = os.getenv("ENTRA_SECRETID")
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEFENDER_API_URL = "https://api.securitycenter.microsoft.com/api/indicators/import"

def obtener_token_defender():
    data = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

# ========================== FUNCIONES =============================
def calcular_expiracion(dias_validez: int) -> str:
    expiracion = datetime.utcnow() + timedelta(days=dias_validez)
    return expiracion.strftime("%Y-%m-%dT%H:%M:%SZ")

def extraer_indicadores_generico(ruta: Path):
    with open(ruta, "r", encoding="utf-8") as f:
        data = json.load(f)

    response = data.get("response", {})
    clave_ioc = next((k for k in response if isinstance(response[k], list)), None)
    if not clave_ioc:
        print("❌ No se encontró lista de indicadores en el archivo.")
        return None, []

    tipo_ioc = ruta.stem.split("_")[0] + "_" + ruta.stem.split("_")[1]
    items = response.get(clave_ioc, [])
    valores = [item.get("valor") for item in items if "valor" in item]
    return tipo_ioc, valores

def validar_indicador(valor: str, tipo: str) -> bool:
    if tipo == "ioc_urls":
        try:
            parsed = urlparse(valor)
            return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
        except Exception:
            return False
    elif tipo == "ioc_ips":
        return re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", valor) is not None
    elif tipo == "ioc_dominios":
        return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$", valor) is not None
    elif tipo == "ioc_hashes":
        return re.match(r"^[A-Fa-f0-9]{64}$", valor) is not None  # SHA-256
    elif tipo == "ioc_correos":
        return re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", valor) is not None
    elif tipo == "ioc_archivos":
        return len(valor) > 1
    return False

def enviar_iocs_defender(indicadores: list, tipo_ioc: str):
    config = TIPOS_IOC_DEFENDER.get(tipo_ioc)
    if not config:
        print(f"⚠️ Tipo de IOC no soportado: {tipo_ioc}")
        return

    tipo_defender = config["tipo"]
    dias_ttl = config["ttl_dias"]
    expiration = calcular_expiracion(dias_ttl)
    token = obtener_token_defender()

    if not token:
        print("❌ No se pudo autenticar en Defender.")
        return

    # Validar antes de enviar
    indicadores_validos = [i for i in indicadores if validar_indicador(i, tipo_ioc)]
    no_validos = [i for i in indicadores if not validar_indicador(i, tipo_ioc)]

    if not indicadores_validos:
        print("⚠️ No hay indicadores válidos para enviar.")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "Indicators": [
            {
                "indicatorValue": valor,
                "indicatorType": tipo_defender,
                "title": f"IOC CSIRT Chile - {tipo_defender}",
                "application": "CSIRT-Chile",
                "expirationTime": expiration,
                "action": "Alert",
                "severity": "Medium",
                "description": f"Indicador tipo {tipo_defender} detectado por CSIRT Chile.",
                "recommendedActions": "Revisar actividad relacionada.",
                "rbacGroupNames": []
            }
            for valor in indicadores_validos
        ]
    }

    try:
        response = requests.post(DEFENDER_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        print(f"✅ {len(indicadores_validos)} indicadores de tipo {tipo_defender} enviados correctamente.")
        if no_validos:
            print(f"⚠️ {len(no_validos)} indicadores fueron descartados por formato inválido.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error al enviar indicadores a Defender: {e}")
        if response is not None:
            print(response.text)

# ========================== MAIN =============================
def main():
    parser = argparse.ArgumentParser(description="Enviar indicadores CSIRT a Microsoft Defender")
    parser.add_argument("archivo", type=Path, help="Ruta al archivo JSON exportado del CSIRT")
    args = parser.parse_args()

    tipo_ioc, indicadores = extraer_indicadores_generico(args.archivo)

    if indicadores:
        print(f"🔎 Tipo detectado: {tipo_ioc} | Total indicadores: {len(indicadores)}")
        enviar_iocs_defender(indicadores, tipo_ioc)
    else:
        print("⚠️ No se encontraron indicadores válidos para enviar.")

if __name__ == "__main__":
    main()