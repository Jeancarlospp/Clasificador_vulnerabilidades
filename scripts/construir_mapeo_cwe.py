"""Construye la tabla de correspondencias CWE -> OWASP Top 10:2025 / OWASP API Security Top 10:2023.

1. Relaciones OFICIALES: se extraen de los documentos de cada estándar
   - OWASP Top 10:2025, sección "List of Mapped CWEs" (fuentes/owasp-top10/2025/docs/en).
   - OWASP API Security Top 10:2023, sección "References / External" (fuentes/owasp-api/editions/2023/en).
2. Relaciones EXTENDIDAS: CWE que no aparecen en las listas oficiales pero se relacionan con una
   categoría por la jerarquía de MITRE CWE (CWE padre) o por la descripción de la categoría.
   Cada una lleva su justificación y se marca como "extendida" en la tabla.
3. Nombres de los CWE: catálogo oficial de MITRE (fuentes/cwe/cwec_latest.xml.zip).

Salida: vulnminer/datos/mapeo_cwe.json  y  datos/correspondencias_cwe_owasp.csv
"""

import csv
import json
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

BASE = Path(__file__).resolve().parents[1]
DOC_TOP10 = BASE / "fuentes" / "owasp-top10" / "2025" / "docs" / "en"
DOC_API = BASE / "fuentes" / "owasp-api" / "editions" / "2023" / "en"
CWE_ZIP = BASE / "fuentes" / "cwe" / "cwec_latest.xml.zip"

ARCHIVOS_API = {
    "API1:2023": "0xa1-broken-object-level-authorization.md",
    "API2:2023": "0xa2-broken-authentication.md",
    "API3:2023": "0xa3-broken-object-property-level-authorization.md",
    "API4:2023": "0xa4-unrestricted-resource-consumption.md",
    "API5:2023": "0xa5-broken-function-level-authorization.md",
    "API6:2023": "0xa6-unrestricted-access-to-sensitive-business-flows.md",
    "API7:2023": "0xa7-server-side-request-forgery.md",
    "API8:2023": "0xa8-security-misconfiguration.md",
    "API9:2023": "0xa9-improper-inventory-management.md",
    "API10:2023": "0xaa-unsafe-consumption-of-apis.md",
}

# --- Relaciones extendidas hacia OWASP Top 10:2025 (CWE sin categoría oficial) ---------------
EXTENDIDAS_TOP10 = {
    943: ("A05:2025", "Hijo de CWE-74 (Injection) en la jerarquía de MITRE: inyección NoSQL."),
    1336: ("A05:2025", "Hijo de CWE-94 (Code Injection): inyección de plantillas del servidor."),
    1321: ("A08:2025", "Hijo de CWE-915 (A08): modificación no controlada de atributos de objetos (prototipo)."),
    400: ("A06:2025", "Ausencia de límites de recursos: falla de diseño; CWE-799 (control de frecuencia) es oficial de A06."),
    770: ("A06:2025", "Asignación de recursos sin límites ni limitación de frecuencia: falla de diseño (ver CWE-799 en A06)."),
    1333: ("A06:2025", "Expresión regular de complejidad exponencial (ReDoS): agotamiento de recursos por diseño."),
    789: ("A06:2025", "Reserva de memoria con tamaño controlado por el usuario: falta de límites por diseño."),
    250: ("A02:2025", "Ejecución con privilegios innecesarios (p. ej. contenedor como root): configuración insegura."),
    1188: ("A02:2025", "Inicialización con valores por defecto inseguros: configuración insegura."),
    2: ("A02:2025", "Configuración insegura del entorno (CWE-2 es referencia oficial de API8:2023, misconfiguration)."),
    1059: ("A02:2025", "Documentación/inventario insuficiente de la API: superficie expuesta no gestionada (configuración)."),
    204: ("A07:2025", "Respuestas distintas según exista o no el usuario: facilita la enumeración en la autenticación."),
    213: ("A01:2025", "Exposición de información por políticas incompatibles; padre CWE-200 está en A01."),
    388: ("A10:2025", "Categoría de manejo de errores de MITRE: condiciones excepcionales."),
    1287: ("A05:2025", "Validación incorrecta del tipo de entrada; padre CWE-20 está en A05."),
    598: ("A06:2025", "Datos sensibles en la cadena de consulta (GET); padre CWE-201/200."),
}

# --- Relaciones extendidas hacia OWASP API Security Top 10:2023 -------------------------------
EXTENDIDAS_API = {
    566: (["API1:2023"], "Evasión de autorización mediante una clave primaria controlada por el usuario (variante de CWE-639)."),
    862: (["API5:2023"], "Falta de verificación de autorización en una función/endpoint (BFLA)."),
    863: (["API5:2023"], "Autorización incorrecta en una función/endpoint (BFLA)."),
    269: (["API5:2023"], "Gestión incorrecta de privilegios entre funciones de usuario y de administración."),
    287: (["API2:2023"], "Autenticación incorrecta."),
    306: (["API2:2023"], "Función crítica sin autenticación."),
    347: (["API2:2023"], "Verificación incorrecta de la firma (JWT sin firma o sin verificar) — citado en la descripción de API2."),
    613: (["API2:2023"], "Expiración de sesión/token insuficiente — API2 menciona no validar la expiración del JWT."),
    798: (["API2:2023"], "Credenciales o secretos de firma escritos en el código: claves débiles/predecibles (API2)."),
    321: (["API2:2023"], "Clave criptográfica fija usada para firmar o cifrar tokens: claves débiles (API2)."),
    521: (["API2:2023"], "Requisitos de contraseña débiles — citado en la descripción de API2."),
    256: (["API2:2023"], "Contraseñas en texto plano — citado en la descripción de API2."),
    916: (["API2:2023"], "Contraseñas con hash débil — citado en la descripción de API2."),
    522: (["API2:2023"], "Credenciales insuficientemente protegidas."),
    1390: (["API2:2023"], "Autenticación débil."),
    1391: (["API2:2023"], "Credenciales débiles."),
    384: (["API2:2023"], "Fijación de sesión."),
    359: (["API3:2023"], "Exposición de datos personales en propiedades del objeto (antes API3:2019 Excessive Data Exposure)."),
    1333: (["API4:2023"], "ReDoS: consumo de CPU no controlado."),
    789: (["API4:2023"], "Reserva de memoria sin límite."),
    489: (["API8:2023"], "Código de depuración activo — API8 menciona funcionalidades innecesarias habilitadas."),
    215: (["API8:2023"], "Información de depuración expuesta."),
    1004: (["API8:2023"], "Cookie sin HttpOnly: cabeceras/atributos de seguridad ausentes."),
    614: (["API8:2023"], "Cookie sin Secure: TLS/atributos de seguridad ausentes."),
    548: (["API8:2023"], "Listado de directorios expuesto."),
    693: (["API8:2023"], "Mecanismo de protección ausente (cabeceras de seguridad) — citado en API8."),
    346: (["API8:2023"], "Validación de origen incorrecta (CORS) — API8 cita CORS mal configurado."),
    1188: (["API8:2023"], "Valores por defecto inseguros."),
    250: (["API8:2023"], "Servicio/contenedor con privilegios innecesarios."),
    295: (["API10:2023"], "Validación de certificados deshabilitada al consumir otra API (canal no confiable)."),
}

# CWE de alcance amplio cuya categoría API depende del contexto del fragmento
# (se aplican solo si el fragmento consume una API externa; ver vulnminer/caracteristicas.py).
CONTEXTO_CONSUMO_API = {20: "API10:2023", 200: "API10:2023", 295: "API10:2023", 319: "API10:2023"}


def extraer_top10():
    mapa = {}
    for doc in sorted(DOC_TOP10.glob("A*_2025-*.md")):
        categoria = doc.name[:3] + ":2025"
        texto = doc.read_text(encoding="utf-8")
        seccion = texto.split("List of Mapped CWEs", 1)[1] if "List of Mapped CWEs" in texto else ""
        for cwe in re.findall(r"CWE-(\d+)", seccion):
            mapa.setdefault(int(cwe), categoria)
    return mapa


def extraer_api():
    mapa = {}
    for categoria, nombre in ARCHIVOS_API.items():
        texto = (DOC_API / nombre).read_text(encoding="utf-8")
        for cwe in sorted({int(c) for c in re.findall(r"CWE-(\d+)", texto)}):
            mapa.setdefault(cwe, []).append(categoria)
    return mapa


def nombres_cwe(necesarios):
    with zipfile.ZipFile(CWE_ZIP) as z:
        xml = z.read(z.namelist()[0])
    raiz = ET.fromstring(xml)
    nombres = {}
    for elem in raiz.iter():
        if elem.tag.endswith("}Weakness") or elem.tag.endswith("}Category") or elem.tag.endswith("}View"):
            id_ = elem.get("ID")
            if id_ and id_.isdigit() and int(id_) in necesarios:
                nombres[int(id_)] = elem.get("Name")
    # Categorías antiguas que ya no están en el catálogo vigente (nombre histórico de MITRE).
    historicos = {2: "7PK - Environment", 16: "Configuration", 320: "Key Management Errors",
                  388: "7PK - Errors", 1035: "OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities"}
    for cwe, nombre in historicos.items():
        if cwe in necesarios:
            nombres.setdefault(cwe, nombre)
    return nombres


def main():
    top10 = extraer_top10()
    api = extraer_api()
    todos = set(top10) | set(api) | set(EXTENDIDAS_TOP10) | set(EXTENDIDAS_API) | set(CONTEXTO_CONSUMO_API)
    nombres = nombres_cwe(todos)

    salida = {
        "fuentes": {
            "owasp_top10_2025": "https://owasp.org/Top10/2025/ (List of Mapped CWEs)",
            "owasp_api_2023": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/ (References / External)",
            "cwe": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        },
        "owasp2025_oficial": {str(k): v for k, v in sorted(top10.items())},
        "owasp2025_extendida": {str(k): {"categoria": c, "justificacion": j} for k, (c, j) in sorted(EXTENDIDAS_TOP10.items())},
        "api2023_oficial": {str(k): v for k, v in sorted(api.items())},
        "api2023_extendida": {str(k): {"categorias": c, "justificacion": j} for k, (c, j) in sorted(EXTENDIDAS_API.items())},
        "api2023_contexto_consumo": {str(k): v for k, v in sorted(CONTEXTO_CONSUMO_API.items())},
        "nombres_cwe": {str(k): v for k, v in sorted(nombres.items())},
    }
    destino = BASE / "vulnminer" / "datos" / "mapeo_cwe.json"
    destino.parent.mkdir(parents=True, exist_ok=True)
    destino.write_text(json.dumps(salida, indent=1, ensure_ascii=False))

    # Tabla plana de correspondencias (entregable de la fase Sample)
    filas = []
    for cwe in sorted(todos):
        t10 = top10.get(cwe) or (EXTENDIDAS_TOP10.get(cwe) or (None,))[0]
        tipo_t10 = "oficial" if cwe in top10 else ("extendida" if cwe in EXTENDIDAS_TOP10 else "")
        apis = list(api.get(cwe, []))
        tipo_api = "oficial" if apis else ""
        if cwe in EXTENDIDAS_API:
            apis += [c for c in EXTENDIDAS_API[cwe][0] if c not in apis]
            tipo_api = tipo_api + ("+" if tipo_api else "") + "extendida"
        if cwe in CONTEXTO_CONSUMO_API and CONTEXTO_CONSUMO_API[cwe] not in apis:
            apis.append(CONTEXTO_CONSUMO_API[cwe] + " (si consume una API externa)")
            tipo_api = tipo_api + ("+" if tipo_api else "") + "contexto"
        justificacion = " ".join(x for x in [(EXTENDIDAS_TOP10.get(cwe) or (None, ""))[1],
                                            (EXTENDIDAS_API.get(cwe) or (None, ""))[1]] if x)
        filas.append({"cwe": f"CWE-{cwe}", "nombre": nombres.get(cwe, ""), "owasp_top10_2025": t10 or "",
                      "tipo_top10": tipo_t10, "owasp_api_2023": ";".join(apis), "tipo_api": tipo_api,
                      "justificacion": justificacion})
    tabla = BASE / "datos" / "correspondencias_cwe_owasp.csv"
    with tabla.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    print(f"CWE oficiales Top 10:2025: {len(top10)} | CWE oficiales API 2023: {len(api)} | total en la tabla: {len(filas)}")


if __name__ == "__main__":
    main()
