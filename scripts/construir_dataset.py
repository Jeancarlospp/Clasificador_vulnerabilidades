"""Fase SAMPLE: construcción del dataset etiquetado de unidades de código y configuración.

Cada registro es una *unidad* (función, handler, bloque de configuración) obtenida con el mismo
segmentador que usa la herramienta (vulnminer/segmentacion.py), etiquetada como vulnerable
o no vulnerable, con su CWE y sus categorías OWASP Top 10:2025 y OWASP API Security Top 10:2023.

Fuentes (descargadas con scripts/descargar_fuentes.py):
  1. semgrep-rules     pruebas de reglas: líneas marcadas con `ruleid:` (vulnerable) y `ok:` (seguro).
  2. codeql            pruebas de consultas: `$ Alert`, `BAD`, `NOT OK` (vulnerable) / `GOOD`, `OK` (seguro).
  3. benchmark-java    OWASP Benchmark v1.2: casos de prueba con resultado esperado (verdadero/falso).
  4. benchmark-python  OWASP Benchmark for Python v0.1.
  5. kics              pruebas positivas/negativas de consultas para Dockerfile, docker-compose y OpenAPI.
  6. securityeval      ejemplos Python inseguros etiquetados por CWE.
  6b. juice-shop       retos de código de OWASP Juice Shop (variantes vulnerables y corrección correcta).
  6c. vulnerableapp    OWASP VulnerableApp: niveles vulnerables y variantes seguras en Spring Boot.
  7. casos-controlados casos de vulnerabilidades de API desarrollados para este proyecto
                       (datos/casos_controlados, generados con scripts/generar_casos_controlados.py).
  8. benigno           código de aplicaciones reales (FastAPI, NestJS, Express, Spring Boot, Flask).

Salida: datos/dataset.csv (con la columna `particion`: entrenamiento / validacion / prueba).

Uso: python scripts/construir_dataset.py
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from vulnminer.caracteristicas import consume_api  # noqa: E402
from vulnminer.catalogo import cwe_a_api2023, cwe_a_owasp2025, numero_cwe  # noqa: E402
from vulnminer.lexico import COMENTARIO_LINEA, limpiar_codigo  # noqa: E402
from vulnminer.segmentacion import EXT_LENGUAJE, segmentar, tipo_archivo  # noqa: E402

FUENTES = BASE / "fuentes"
DATOS = BASE / "datos"
LENGUAJES = {"java", "python", "javascript", "typescript"}
SEMILLA = 42


def leer(p):
    return Path(p).read_text(encoding="utf-8", errors="ignore")


def registro(fuente, proyecto, archivo, unidad, vulnerable, cwes=(), api_explicitas=(), owasp_explicitas=(), origen=""):
    cwes = sorted({c for c in (numero_cwe(x) for x in cwes) if c})
    consume = consume_api(unidad.texto)
    owasp = set(owasp_explicitas)
    api = set(api_explicitas)
    if vulnerable:
        for c in cwes:
            o = cwe_a_owasp2025(c)
            if o:
                owasp.add(o)
            api.update(cwe_a_api2023(c, consume))
    return dict(
        fuente=fuente, proyecto=proyecto, archivo=archivo, lenguaje=unidad.lenguaje, subtipo=unidad.subtipo,
        unidad=unidad.nombre, linea_inicio=unidad.linea_inicio, linea_fin=unidad.linea_fin,
        codigo=unidad.texto, contexto=unidad.contexto, meta=json.dumps(unidad.meta, ensure_ascii=False),
        vulnerable=int(vulnerable), cwe=";".join(f"CWE-{c}" for c in cwes) if vulnerable else "",
        owasp2025=";".join(sorted(owasp)) if vulnerable else "", api2023=";".join(sorted(api, key=lambda x: int(x[3:].split(":")[0]))) if vulnerable else "",
        origen_etiqueta=origen,
    )


def etiquetar_unidades(fuente, proyecto, ruta_rel, texto, objetivos, lenguaje=None, subtipo=None, origen=""):
    """objetivos: {nº de línea 1-based: (etiqueta, set_cwe)} -> registros de las unidades que los contienen."""
    filas = []
    for u in segmentar(ruta_rel, texto, lenguaje, subtipo):
        dentro = [objetivos[l] for l in u.lineas if l in objetivos]
        if not dentro:
            continue
        vul = [o for o in dentro if o[0] == 1]
        if vul:
            cwes = set().union(*[o[1] for o in vul])
            filas.append(registro(fuente, proyecto, ruta_rel, u, 1, cwes, origen=origen))
        else:
            filas.append(registro(fuente, proyecto, ruta_rel, u, 0, origen=origen))
    return filas


def lenguaje_y_subtipo(ruta):
    """Tipo de un archivo de prueba (los nombres de prueba no siempre siguen la convención)."""
    nombre = ruta.name.lower()
    if ruta.suffix in EXT_LENGUAJE:
        leng = EXT_LENGUAJE[ruta.suffix]
        return (leng, "codigo") if leng in LENGUAJES else None
    if nombre.endswith(".dockerfile") or nombre == "dockerfile":
        return "config", "dockerfile"
    if ruta.suffix == ".properties":
        return "config", "properties"
    if ruta.suffix in (".yaml", ".yml", ".json"):
        texto = leer(ruta)[:3000]
        if re.search(r"^\s*[\"']?(openapi|swagger)[\"']?\s*:", texto, re.M):
            return "config", "openapi"
        if ruta.suffix != ".json" and re.search(r"^services\s*:", texto, re.M):
            return "config", "compose"
        if ruta.suffix != ".json" and re.search(r"^(spring|server|management|logging)\s*:", texto, re.M):
            return "config", "yaml"
    return None


# ---------------------------------------------------------------------------------------------
# 1. semgrep-rules
# ---------------------------------------------------------------------------------------------
# Correcciones de metadatos de Semgrep: reglas cuyo CWE declarado no corresponde a la vulnerabilidad que
# detectan (verificado comparando el id y la descripción de cada regla con su CWE).
CORRECCIONES_SEMGREP = {
    "tainted-sql-string": {89}, "node-postgres-sqli": {89},                 # declaraban CWE-704 / CWE-915
    "jwt-none-alg": {347}, "jwt-python-none-alg": {347}, "jjwt-none-alg": {347}, "java-jwt-none-alg": {347},  # CWE-327
    "cors-regex-wildcard": {942}, "nestjs-header-cors-any": {942}, "permissive-cors": {942},              # CWE-183
    "puppeteer-evaluate-code-injection": {94}, "puppeteer-evaluate-arg-injection": {94},                   # CWE-918
    "playwright-evaluate-code-injection": {94}, "playwright-evaluate-arg-injection": {94},
}

ANOTACION_SEMGREP = re.compile(r"(todoruleid|ruleid|todook|deepok|deepruleid|ok)\s*:\s*([\w.\-, ]+)")


def cargar_semgrep():
    raiz = FUENTES / "semgrep-rules"
    filas = []
    for yml in sorted(raiz.rglob("*.yaml")):
        if yml.name.endswith(".test.yaml") or any(p in yml.parts for p in ("scripts", "stats", "kubernetes", "github-actions",
                                                                           "gitlab", "argo", "semgrep", "generic", "json")):
            continue
        try:
            doc = yaml.safe_load(leer(yml))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict) or not doc.get("rules"):
            continue
        reglas = {}
        for r in doc["rules"]:
            meta = r.get("metadata") or {}
            if meta.get("category") != "security":
                continue
            cwes = meta.get("cwe", [])
            cwes = cwes if isinstance(cwes, list) else [cwes]
            if r.get("id") in CORRECCIONES_SEMGREP:
                reglas[r.get("id")] = set(CORRECCIONES_SEMGREP[r.get("id")])
                continue
            reglas[r.get("id")] = {c for c in (numero_cwe(re.search(r"CWE-\d+", str(x)).group(0)) if re.search(r"CWE-\d+", str(x)) else None
                                               for x in cwes) if c}
        if not reglas:
            continue
        for prueba in yml.parent.glob(yml.stem + ".*"):
            if prueba == yml or ".fixed." in prueba.name:
                continue
            t = lenguaje_y_subtipo(prueba)
            if not t:
                continue
            lineas = leer(prueba).splitlines()
            objetivos, pendiente = {}, None
            for i, linea in enumerate(lineas):
                m = ANOTACION_SEMGREP.search(linea) if COMENTARIO_LINEA.match(linea) else None
                if m:
                    tipo, ids = m.group(1), [x.strip() for x in m.group(2).split(",")]
                    etiqueta = 1 if "ruleid" in tipo else 0
                    cwes = set()
                    for rid in ids:
                        cwes |= reglas.get(rid, reglas.get(rid.split(".")[-1], set()))
                    pendiente = (etiqueta, cwes)
                    continue
                if pendiente and linea.strip() and not COMENTARIO_LINEA.match(linea):
                    if i + 1 not in objetivos or pendiente[0] == 1:
                        objetivos[i + 1] = pendiente
                    pendiente = None
            rel = str(prueba.relative_to(raiz))
            filas += etiquetar_unidades("semgrep-rules", f"semgrep:{prueba.parent.relative_to(raiz)}", rel, "\n".join(lineas),
                                        objetivos, *t, origen="anotación de la prueba de la regla")
    return filas


# ---------------------------------------------------------------------------------------------
# 2. CodeQL
# ---------------------------------------------------------------------------------------------
VULN_CODEQL = re.compile(r"\$\s*(MISSING\s*:\s*)?Alert|(#|//|/\*)\s*(BAD|NOT\s+OK)\b|\$\s*(MISSING\s*:\s*)?(Sink|hasTaintFlow)\b", re.I)
SEGURO_CODEQL = re.compile(r"\$\s*SPURIOUS\s*:\s*Alert|(#|//|/\*)\s*(GOOD|OK)\b(?!\s*\()", re.I)


def cargar_codeql():
    raiz = FUENTES / "codeql"
    filas = []
    for archivo in sorted(raiz.rglob("*")):
        if not archivo.is_file():
            continue
        cwe_dir = next((p for p in archivo.parts if re.match(r"CWE-\d+$", p, re.I)), None)
        if not cwe_dir:
            continue
        t = lenguaje_y_subtipo(archivo)
        if not t:
            continue
        cwe = numero_cwe(cwe_dir)
        texto = leer(archivo)
        lineas = texto.splitlines()
        rel = str(archivo.relative_to(raiz))
        proyecto = f"codeql:{archivo.parent.relative_to(raiz)}"
        if t[1] != "codigo":
            # configuraciones de prueba en carpetas good/ y bad/
            partes = {p.lower() for p in archivo.parts}
            if "bad" in partes or "good" in partes:
                etiqueta = 1 if "bad" in partes else 0
                objetivos = {i + 1: (etiqueta, {cwe} if etiqueta else set()) for i, l in enumerate(lineas) if l.strip()}
                filas += etiquetar_unidades("codeql-tests", proyecto, rel, texto, objetivos, *t, origen="carpeta good/bad de la prueba")
            continue
        objetivos, pendiente = {}, None
        for i, linea in enumerate(lineas):
            es_coment = bool(COMENTARIO_LINEA.match(linea))
            etiqueta = 1 if VULN_CODEQL.search(linea) else (0 if SEGURO_CODEQL.search(linea) else None)
            if es_coment:
                if etiqueta is not None:
                    pendiente = etiqueta
                continue
            if not linea.strip():
                continue
            if etiqueta is None and pendiente is not None:
                etiqueta = pendiente
            pendiente = None
            if etiqueta is not None:
                objetivos[i + 1] = (etiqueta, {cwe} if etiqueta else set())
        filas += etiquetar_unidades("codeql-tests", proyecto, rel, texto, objetivos, *t, origen="anotación de la prueba de la consulta")
    return filas


# ---------------------------------------------------------------------------------------------
# 3-4. OWASP Benchmark (Java y Python)
# ---------------------------------------------------------------------------------------------
def _benchmark(nombre, carpeta, csv, ext, funcion_objetivo, max_casos):
    raiz = FUENTES / nombre
    esperados = pd.read_csv(raiz / csv, comment="#", header=None, names=["test", "categoria", "es_vulnerable", "cwe"],
                            skipinitialspace=True)
    esperados["es_vulnerable"] = esperados["es_vulnerable"].astype(str).str.strip().str.lower() == "true"
    # muestreo estratificado por categoría y resultado para no dominar el dataset
    partes = []
    for _, g in esperados.groupby(["categoria", "es_vulnerable"]):
        n = min(len(g), max(8, int(max_casos * len(g) / len(esperados))))
        partes.append(g.sample(n, random_state=SEMILLA))
    muestra = pd.concat(partes)
    filas = []
    for _, fila in muestra.iterrows():
        archivo = raiz / carpeta / f"{fila.test}{ext}"
        if not archivo.exists():
            continue
        texto = leer(archivo)
        rel = str(archivo.relative_to(raiz))
        for u in segmentar(rel, texto):
            if re.search(funcion_objetivo, u.nombre):
                filas.append(registro(f"owasp-{nombre}", f"{nombre}:{fila.test}", rel, u, int(fila.es_vulnerable),
                                      {int(fila.cwe)} if fila.es_vulnerable else set(), origen="resultado esperado del Benchmark"))
    return filas


def cargar_benchmark():
    return (_benchmark("benchmark-java", "src/main/java/org/owasp/benchmark/testcode", "expectedresults-1.2.csv", ".java",
                       r"^doPost", 900)
            + _benchmark("benchmark-python", "testcode", "expectedresults-0.1.csv", ".py", r"_post$", 600))


# ---------------------------------------------------------------------------------------------
# 5. KICS (Dockerfile, docker-compose, OpenAPI) — consultas de seguridad seleccionadas
# ---------------------------------------------------------------------------------------------
API8, API2, API3, API4 = ["API8:2023"], ["API2:2023"], ["API3:2023"], ["API4:2023"]
KICS = {
    # docker-compose
    "container_capabilities_unrestricted": (250, API8), "default_seccomp_profile_disabled": (250, API8),
    "docker_socket_mounted_in_container": (250, API8), "host_namespace_is_shared": (250, API8),
    "shared_host_ipc_namespace": (250, API8), "shared_host_network_namespace": (250, API8),
    "shared_host_user_namespace": (250, API8), "no_new_privileges_not_set": (250, API8),
    "privileged_containers_enabled": (250, API8), "volume_has_sensitive_host_directory": (668, API8),
    "container_traffic_not_bound_to_host_interface": (16, API8), "memory_not_limited": (770, API4),
    "pids_limit_not_set": (770, API4), "cpus_not_limited": (770, API4),
    # Dockerfile
    "add_instead_of_copy": (494, []), "apt_get_install_pin_version_not_defined": (1357, []),
    "gem_install_without_version": (1357, []), "image_version_not_explicit": (1357, []),
    "image_version_using_latest": (1357, []), "missing_version_specification_in_dnf_install": (1357, []),
    "npm_install_without_pinned_version": (1357, []), "unpinned_package_version_in_apk_add": (1357, []),
    "unpinned_package_version_in_pip_install": (1357, []), "yum_install_without_version": (1357, []),
    "zypper_install_without_version": (1357, []), "last_user_is_root": (250, API8),
    "missing_user_instruction": (250, API8), "run_using_sudo": (250, API8), "exposing_port_22": (16, API8),
    # OpenAPI
    "global_schemes_uses_http": (319, API8), "path_scheme_accepts_http": (319, API8), "schemes_uses_http copy": (319, API8),
    "global_server_uses_http": (319, API8), "path_server_uses_http": (319, API8),
    "cleartext_credentials_with_basic_auth_for_operation": (287, API2), "operation_using_basic_auth": (287, API2),
    "security_definitions_using_basic_auth": (287, API2), "global_security_scheme_using_basic_authentication": (287, API2),
    "security_scheme_using_http_basic": (287, API2), "implicit_flow_oauth2": (287, API2),
    "oauth2_with_implicit_flow": (287, API2), "operation_using_implicit_flow": (287, API2),
    "global_security_using_password_flow": (287, API2), "oauth2_with_password_flow": (287, API2),
    "security_definitions_allows_password_flow": (287, API2), "operation_using_password_flow": (287, API2),
    "api_key_exposed_in_global_security": (598, API2), "api_key_exposed_in_operation_security": (598, API2),
    "security_definitions_undefined_or_empty": (306, API2), "global_security_field_undefined": (306, API2),
    "no_global_and_operation_security_defined": (306, API2), "security_empty_array": (306, API2),
    "security_empty_object_definition": (306, API2), "security_operations_empty_array": (306, API2),
    "security_operations_empty_object_definition": (306, API2), "security_scheme_undefined": (306, API2),
    "additional_properties_too_permissive": (915, API3), "array_without_maximum_number_items": (770, API4),
    "maximum_length_undefined": (770, API4), "numeric_schema_without_maximum": (770, API4),
}


def cargar_kics():
    raiz = FUENTES / "kics" / "assets" / "queries"
    filas = []
    for meta in sorted(raiz.rglob("metadata.json")):
        consulta = meta.parent.name
        if consulta not in KICS:
            continue
        cwe, api = KICS[consulta]
        dir_test = meta.parent / "test"
        if not dir_test.exists():
            continue
        esperados = defaultdict(set)
        archivo_esperado = dir_test / "positive_expected_result.json"
        if archivo_esperado.exists():
            for e in json.loads(leer(archivo_esperado)):
                nombre_esp = e.get("filename") or e.get("fileName") or "positive.yaml"
                esperados[Path(nombre_esp).name].add(int(e.get("line", 0)))
        for prueba in sorted(dir_test.iterdir()):
            if prueba.name.endswith("expected_result.json") or prueba.is_dir():
                continue
            t = lenguaje_y_subtipo(prueba) or (("config", "dockerfile") if "dockerfile" in str(meta.parent).lower() else None)
            if not t and "dockerCompose" in str(meta):
                t = ("config", "compose")
            if not t:
                continue
            rel = str(prueba.relative_to(raiz))
            proyecto = f"kics:{meta.parent.relative_to(raiz)}"
            texto = leer(prueba)
            unidades = segmentar(rel, texto, *t)
            if prueba.name.startswith("negative"):
                filas += [registro("kics", proyecto, rel, u, 0, origen="prueba negativa de la consulta") for u in unidades]
                continue
            if not prueba.name.startswith("positive"):
                continue
            lineas_esp = esperados.get(prueba.name, set())
            if unidades and unidades[0].meta.get("lineas_aproximadas"):
                # OpenAPI en JSON: se identifica la unidad por la clave JSON de la línea esperada
                lineas_txt = texto.splitlines()
                elegidas = set()
                for l in lineas_esp:
                    m = re.search(r'"([^"]+)"\s*:', lineas_txt[l - 1]) if 0 < l <= len(lineas_txt) else None
                    if not m:
                        continue
                    candidatas = [k for k, u in enumerate(unidades)
                                  if re.search(r"(^|\s|')" + re.escape(m.group(1)) + r"'?\s*:", u.texto, re.M)]
                    if len(candidatas) == 1:
                        elegidas.add(candidatas[0])
                marcadas = [unidades[k] for k in sorted(elegidas)]
            else:
                marcadas = [u for u in unidades if lineas_esp & set(u.lineas)]
            for u in marcadas:
                filas.append(registro("kics", proyecto, rel, u, 1, {cwe}, api_explicitas=api,
                                      origen="prueba positiva de la consulta"))
    return filas


# ---------------------------------------------------------------------------------------------
# 6. SecurityEval
# ---------------------------------------------------------------------------------------------
def cargar_securityeval():
    filas = []
    for linea in leer(FUENTES / "securityeval" / "dataset.jsonl").splitlines():
        ej = json.loads(linea)
        cwe = numero_cwe(re.search(r"CWE-\d+", ej["ID"]).group(0))
        codigo = ej.get("Insecure_code") or ""
        for u in segmentar(ej["ID"], codigo, "python", "codigo"):
            if u.nombre != "bloque de módulo":
                filas.append(registro("securityeval", f"securityeval:{ej['ID']}", ej["ID"], u, 1, {cwe},
                                      origen="ejemplo inseguro etiquetado por CWE"))
    return filas


# ---------------------------------------------------------------------------------------------
# 6b. OWASP Juice Shop: retos de código (código real de producción en TypeScript)
# ---------------------------------------------------------------------------------------------
# Cada reto tiene varias propuestas de corrección: las incorrectas siguen siendo vulnerables y la
# marcada como `_correct` no lo es. Se excluyen los retos de LLM (chatbot), Web3 y Solidity.
JUICE_SHOP = {
    "accessLogDisclosureChallenge": (548, ["API8:2023"]), "directoryListingChallenge": (548, ["API8:2023"]),
    "adminSectionChallenge": (862, ["API5:2023"]), "changeProductChallenge": (862, ["API5:2023"]),
    "dbSchemaChallenge": (89, []), "unionSqlInjectionChallenge": (89, []), "loginAdminChallenge": (89, []),
    "loginBenderChallenge": (89, []), "loginJimChallenge": (89, []),
    "exposedMetricsChallenge": (200, ["API8:2023"]), "forgedReviewChallenge": (639, ["API1:2023"]),
    "localXssChallenge": (79, []), "restfulXssChallenge": (79, []), "xssBonusChallenge": (79, []),
    "noSqlReviewsChallenge": (943, []), "passkeySignatureChallenge": (347, ["API2:2023"]),
    "passkeyCredentialOverwriteChallenge": (287, ["API2:2023"]), "redirectChallenge": (601, []),
    "redirectCryptoCurrencyChallenge": (601, []), "registerAdminChallenge": (915, ["API3:2023"]),
    "resetPasswordBenderChallenge": (640, ["API2:2023"]), "resetPasswordBjoernChallenge": (640, ["API2:2023"]),
    "resetPasswordBjoernOwaspChallenge": (640, ["API2:2023"]), "resetPasswordJimChallenge": (640, ["API2:2023"]),
    "resetPasswordMortyChallenge": (640, ["API2:2023"]), "resetPasswordUvoginChallenge": (640, ["API2:2023"]),
    "weakPasswordChallenge": (521, ["API2:2023"]),
}


def cargar_juice_shop():
    carpeta = FUENTES / "juice-shop-codefixes" / "data" / "static" / "codefixes"
    if not carpeta.exists():
        return []
    filas = []
    for reto, (cwe, api) in JUICE_SHOP.items():
        variantes = sorted(carpeta.glob(f"{reto}_*.ts"))
        correctas = [v for v in variantes if v.stem.endswith("_correct")]
        if not correctas:
            continue
        norm = lambda u: re.sub(r"\s+", " ", limpiar_codigo(u.texto)).strip()  # noqa: E731
        unidades = {v: segmentar(v.name, leer(v), "typescript", "codigo") for v in variantes}
        en_correcta = {norm(u) for v in correctas for u in unidades[v]}
        en_incorrectas = {norm(u) for v in variantes if v not in correctas for u in unidades[v]}
        for v in variantes:
            correcta = v in correctas
            for u in unidades[v]:
                n = norm(u)
                # solo cuentan las unidades que difieren entre la corrección correcta y las incorrectas
                if correcta and n not in en_incorrectas:
                    filas.append(registro("juice-shop", f"juice-shop:{reto}", v.name, u, 0, origen="corrección correcta del reto de código"))
                elif not correcta and n not in en_correcta:
                    filas.append(registro("juice-shop", f"juice-shop:{reto}", v.name, u, 1, {cwe}, api_explicitas=api,
                                          origen="propuesta de corrección incorrecta (sigue vulnerable)"))
    return filas


# ---------------------------------------------------------------------------------------------
# 6c. OWASP VulnerableApp (SasanLabs): niveles vulnerables y variantes seguras en Spring Boot
# ---------------------------------------------------------------------------------------------
# Cada vulnerabilidad tiene varios niveles; los marcados con `variant = Variant.SECURE` son seguros.
# Las anotaciones propias del proyecto (@AttackVector, @VulnerableAppRequestMapping...) y los nombres
# `...Level3` delatan la etiqueta, por lo que se eliminan conservando el número de líneas.
VULNERABLEAPP = {
    "sqlInjection": (89, []), "commandInjection": (78, []), "ldapInjection": (90, []), "xss": (79, []),
    "xxe": (611, []), "pathTraversal": (22, []), "ssrf": (918, ["API7:2023"]), "openRedirect": (601, []),
    "idor": (639, ["API1:2023"]), "jwt": (347, ["API2:2023"]), "deserialization": (502, []),
    "fileupload": (434, []), "cryptographicFailures": (327, []), "passwordReset": (640, ["API2:2023"]),
    "sessionManagement": (384, ["API2:2023"]), "otp": (307, ["API2:2023"]), "authentication": (287, ["API2:2023"]),
}


def _quitar_anotacion(texto, nombre, marcas=None):
    while True:
        m = re.search(r"@" + nombre + r"\s*\(", texto)
        if not m:
            return texto
        i, profundidad = m.end(), 1
        while profundidad and i < len(texto):
            profundidad += {"(": 1, ")": -1}.get(texto[i], 0)
            i += 1
        bloque = texto[m.start():i]
        if marcas is not None:
            marcas.append((texto[:m.start()].count("\n") + 1, "Variant.SECURE" in bloque))
            reemplazo = '@GetMapping("/consulta")' + "\n" * bloque.count("\n")
        else:
            reemplazo = "\n" * bloque.count("\n")
        texto = texto[:m.start()] + reemplazo + texto[i:]


def cargar_vulnerableapp():
    raiz = FUENTES / "vulnerableapp" / "src" / "main" / "java" / "org" / "sasanlabs" / "service" / "vulnerability"
    if not raiz.exists():
        return []
    filas = []
    for paquete, (cwe, api) in VULNERABLEAPP.items():
        for archivo in sorted((raiz / paquete).rglob("*.java")):
            texto = leer(archivo)
            if "VulnerableAppRequestMapping" not in texto:
                continue
            marcas = []
            texto = _quitar_anotacion(texto, "AttackVector")
            texto = _quitar_anotacion(texto, "ChallengeCard")
            texto = _quitar_anotacion(texto, "VulnerableAppRestController")
            texto = _quitar_anotacion(texto, "VulnerableAppRequestMapping", marcas)
            texto = re.sub(r"(?<=\w)Level\d+\b", "Handler", texto)
            texto = re.sub(r"\bLEVEL_\d+\b", "NIVEL", texto)
            rel = str(archivo.relative_to(raiz))
            unidades = segmentar(rel, texto, "java", "codigo")
            for linea, seguro in marcas:
                u = next((u for u in unidades if linea in u.lineas), None)
                if u is None:
                    continue
                if seguro:
                    filas.append(registro("vulnerableapp", f"vulnerableapp:{rel}", rel, u, 0, origen="variante segura del laboratorio"))
                else:
                    filas.append(registro("vulnerableapp", f"vulnerableapp:{rel}", rel, u, 1, {cwe}, api_explicitas=api,
                                          origen="nivel vulnerable del laboratorio"))
    return filas


# ---------------------------------------------------------------------------------------------
# 7. Casos controlados
# ---------------------------------------------------------------------------------------------
def cargar_controlados():
    raiz = DATOS / "casos_controlados"
    manifiesto = raiz / "manifiesto.json"
    if not manifiesto.exists():
        print("  (sin casos controlados: ejecute scripts/generar_casos_controlados.py)")
        return []
    filas = []
    for caso in json.loads(leer(manifiesto)):
        ruta = raiz / caso["archivo"]
        texto = leer(ruta)
        for u in segmentar(caso["archivo"], texto):
            objetivo = caso.get("funcion")
            linea = caso.get("linea")
            if (objetivo and u.nombre.split(" (parte")[0] == objetivo) or (linea and linea in u.lineas):
                filas.append(registro("casos-controlados", f"controlado:{caso['grupo']}", caso["archivo"], u, caso["vulnerable"],
                                      caso.get("cwe", []), api_explicitas=caso.get("api2023", []),
                                      owasp_explicitas=caso.get("owasp2025", []), origen="caso controlado (etiqueta por diseño)"))
    return filas


# ---------------------------------------------------------------------------------------------
# 8. Código benigno de aplicaciones reales
# ---------------------------------------------------------------------------------------------
EXCLUIR_BENIGNO = re.compile(r"(^|/)(node_modules|dist|build|target|tests?|__tests__|spec|e2e|migrations?|alembic|docs?|"
                             r"\.git|vendor|static|public|scripts|examples?|demo)(/|$)|\.(spec|test|d)\.(ts|js)$|_test\.py$|test_\w+\.py$|\.min\.js$")
# indicadores de problemas evidentes: esas unidades se descartan de la clase segura (posible ruido de etiqueta)
DUDOSO = re.compile(r"secret\w*\s*[:=]\s*['\"][^'\"]{6,}|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|\bmd5\b|\bsha1\b|"
                    r"\beval\s*\(|shell\s*=\s*True|pickle\.loads|innerHTML", re.I)


# Indicadores de configuración insegura: las unidades de configuración de proyectos reales que los
# activan no se usan como ejemplos "no vulnerables", porque no se puede asegurar que sean seguras.
CONFIG_DUDOSA = ["secreto_literal", "debug_activo", "cors_permisivo", "actuator_expuesto", "consola_bd", "tls_desactivado",
                 "contenedor_root", "imagen_sin_version", "descarga_remota", "paquete_sin_version", "csrf_desactivado",
                 "http_texto_claro", "openapi_sin_seguridad", "documentacion_expuesta", "puerto_sensible"]


def configuracion_dudosa(u):
    from vulnminer.caracteristicas import COMPILADOS, INDICE

    if u.subtipo == "dockerfile" and not u.meta.get("archivo_tiene_user", True):
        return True
    return any(COMPILADOS[INDICE[n]][1].search(u.texto) for n in CONFIG_DUDOSA)


def cargar_benigno(max_por_proyecto=600, max_config=150):
    from vulnminer.descubrimiento import es_generado

    raiz = FUENTES / "benigno"
    filas = []
    rng = np.random.default_rng(SEMILLA)
    from desarrollo import PROYECTOS_BENIGNOS_DESARROLLO

    for proyecto in sorted(p for p in raiz.iterdir() if p.is_dir()):
        if proyecto.name in PROYECTOS_BENIGNOS_DESARROLLO:
            continue  # reservados para el conjunto de desarrollo
        candidatas = []
        for archivo in sorted(proyecto.rglob("*")):
            rel = str(archivo.relative_to(raiz))
            if not archivo.is_file() or EXCLUIR_BENIGNO.search(rel.lower()):
                continue
            t = tipo_archivo(archivo)
            if not t or (t[1] == "codigo" and t[0] not in LENGUAJES) or t[1] == "env":
                continue
            texto = leer(archivo)
            if es_generado(archivo.name, texto):
                continue
            for u in segmentar(rel, texto, *t):
                if len(u.lineas) < 2 or DUDOSO.search(u.texto):
                    continue
                if u.subtipo != "codigo" and configuracion_dudosa(u):
                    continue
                # en las muestras de NestJS cada ejemplo es un proyecto independiente
                grupo = "/".join(Path(rel).parts[:3]) if "nest-samples" in rel else proyecto.name
                candidatas.append((grupo, rel, u))
        seleccion = []
        for es_config, tope in ((False, max_por_proyecto), (True, max_config)):
            grupo_c = [c for c in candidatas if (c[2].subtipo != "codigo") == es_config]
            if len(grupo_c) > tope:
                idx = rng.choice(len(grupo_c), tope, replace=False)
                grupo_c = [grupo_c[i] for i in sorted(idx)]
            seleccion += grupo_c
        for grupo, rel, u in seleccion:
            origen = ("configuración de un proyecto open source sin indicadores de configuración insegura"
                      if u.subtipo != "codigo" else "código de producción de un proyecto open source")
            filas.append(registro("benigno", f"benigno:{grupo}", rel, u, 0, origen=origen))
    return filas


# ---------------------------------------------------------------------------------------------
# Limpieza, balance y partición
# ---------------------------------------------------------------------------------------------
def limpiar(df):
    n0 = len(df)
    df = df[df["codigo"].str.strip().str.len() >= 20].copy()
    df["_norm"] = df["codigo"].map(lambda c: re.sub(r"\s+", " ", limpiar_codigo(c)).strip())
    df = df[df["_norm"].str.len() >= 20]
    # códigos idénticos con etiquetas contradictorias se descartan
    conflicto = df.groupby("_norm")["vulnerable"].nunique()
    df = df[~df["_norm"].isin(conflicto[conflicto > 1].index)]
    df = df.sort_values("vulnerable", ascending=False).drop_duplicates("_norm")
    # vulnerables sin ninguna categoría OWASP (p. ej. seguridad de memoria) no aportan al objetivo
    df = df[(df["vulnerable"] == 0) | (df["owasp2025"] != "")]
    print(f"  limpieza: {n0} -> {len(df)} registros (duplicados, conflictos y sin categoría)")
    return df.drop(columns="_norm")


def balancear(df, max_por_archivo=12, max_por_cwe=420):
    rng = SEMILLA
    df = df.sample(frac=1.0, random_state=rng)
    df = df.groupby(["archivo", "vulnerable"], group_keys=False).head(max_por_archivo)
    vul = df[df["vulnerable"] == 1].copy()
    vul["_cwe1"] = vul["cwe"].str.split(";").str[0]
    vul = vul.groupby(["fuente", "_cwe1"], group_keys=False).head(max_por_cwe).drop(columns="_cwe1")
    return pd.concat([vul, df[df["vulnerable"] == 0]])


def particionar(df, prop=(0.70, 0.15, 0.15)):
    """Partición 70/15/15 por grupo de origen con estratificación iterativa multietiqueta.

    - Todas las unidades de un grupo (proyecto, directorio de pruebas de una regla, familia de
      casos controlados) quedan en la misma partición: no hay fugas entre particiones.
    - Los grupos se asignan de la etiqueta más escasa a la más frecuente; cada grupo va a la
      partición con mayor déficit relativo para su etiqueta más escasa (estratificación iterativa
      de Sechidis et al., 2011, aplicada a grupos). Así cada categoría OWASP aparece en las tres
      particiones cuando hay suficientes grupos que la contienen.
    """
    nombres = ("entrenamiento", "validacion", "prueba")
    etiquetas_unidad = []
    for r in df.itertuples(index=False):
        if r.vulnerable:
            e = set(filter(None, r.owasp2025.split(";"))) | set(filter(None, r.api2023.split(";")))
        else:
            e = {"seguro"}
        e.add(f"subtipo:{r.subtipo}")
        etiquetas_unidad.append(e)
    df = df.assign(_e=etiquetas_unidad)
    grupos = {}
    for g, sub in df.groupby("proyecto"):
        conteo = defaultdict(int)
        for e in sub["_e"]:
            for x in e:
                conteo[x] += 1
        grupos[g] = (len(sub), dict(conteo))
    total = defaultdict(int)
    for _, (_, c) in grupos.items():
        for x, n in c.items():
            total[x] += n
    objetivo = {p: {x: prop[k] * n for x, n in total.items()} for k, p in enumerate(nombres)}
    objetivo_tam = {p: prop[k] * len(df) for k, p in enumerate(nombres)}
    actual = {p: defaultdict(float) for p in nombres}
    tam = {p: 0 for p in nombres}
    rng = np.random.default_rng(SEMILLA)
    orden = list(grupos)
    rng.shuffle(orden)
    # primero los grupos que contienen las etiquetas más escasas
    orden.sort(key=lambda g: min(total[x] for x in grupos[g][1] if not x.startswith("subtipo:"))
               if any(not x.startswith("subtipo:") for x in grupos[g][1]) else 10**9)
    asignacion = {}
    for g in orden:
        n, conteo = grupos[g]
        clave = [x for x in conteo if not x.startswith("subtipo:")] or list(conteo)
        rara = min(clave, key=lambda x: total[x])
        deficit = {p: (objetivo[p][rara] - actual[p][rara]) / max(objetivo[p][rara], 1e-9) for p in nombres}
        deficit_tam = {p: (objetivo_tam[p] - tam[p]) / objetivo_tam[p] for p in nombres}
        elegido = max(nombres, key=lambda p: (round(deficit[p], 3), deficit_tam[p]))
        asignacion[g] = elegido
        tam[elegido] += n
        for x, c in conteo.items():
            actual[elegido][x] += c
    return df["proyecto"].map(asignacion).values


def main():
    cargadores = [("semgrep", cargar_semgrep), ("codeql", cargar_codeql), ("benchmark", cargar_benchmark),
                  ("kics", cargar_kics), ("securityeval", cargar_securityeval), ("juice-shop", cargar_juice_shop),
                  ("vulnerableapp", cargar_vulnerableapp),
                  ("controlados", cargar_controlados),
                  ("benigno", cargar_benigno)]
    filas = []
    for nombre, f in cargadores:
        nuevas = f()
        print(f"{nombre:12s}: {len(nuevas):6d} unidades ({sum(r['vulnerable'] for r in nuevas)} vulnerables)")
        filas += nuevas
    df = pd.DataFrame(filas)
    df = limpiar(df)
    df = balancear(df)
    df["particion"] = particionar(df.reset_index(drop=True))
    df = df.sort_values(["particion", "fuente", "archivo", "linea_inicio"]).reset_index(drop=True)
    df.insert(0, "id", [f"u{i:05d}" for i in range(len(df))])
    DATOS.mkdir(exist_ok=True)
    df.to_csv(DATOS / "dataset.csv", index=False)

    print(f"\nTotal: {len(df)} unidades | vulnerables: {df.vulnerable.sum()} | no vulnerables: {(df.vulnerable == 0).sum()}")
    print(df.groupby(["fuente", "vulnerable"]).size().unstack(fill_value=0))
    print(df.groupby(["particion", "vulnerable"]).size().unstack(fill_value=0))
    print(df["lenguaje"].value_counts())
    for col in ("owasp2025", "api2023"):
        print(df[df.vulnerable == 1][col].str.split(";").explode().replace("", np.nan).dropna().value_counts().sort_index())


if __name__ == "__main__":
    main()
