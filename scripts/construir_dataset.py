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
                    if etiqueta and not cwes:
                        cwes = set().union(*reglas.values())
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
                             r"\.git|vendor|static|public|scripts)(/|$)|\.(spec|test|d)\.(ts|js)$|_test\.py$|test_\w+\.py$|\.min\.js$")
# indicadores de problemas evidentes: esas unidades se descartan de la clase segura (posible ruido de etiqueta)
DUDOSO = re.compile(r"secret\w*\s*[:=]\s*['\"][^'\"]{6,}|verify\s*=\s*False|rejectUnauthorized\s*:\s*false|\bmd5\b|\bsha1\b|"
                    r"\beval\s*\(|shell\s*=\s*True|pickle\.loads|innerHTML", re.I)


def cargar_benigno(max_por_proyecto=1600):
    raiz = FUENTES / "benigno"
    filas = []
    rng = np.random.default_rng(SEMILLA)
    for proyecto in sorted(p for p in raiz.iterdir() if p.is_dir()):
        candidatas = []
        for archivo in sorted(proyecto.rglob("*")):
            rel = str(archivo.relative_to(raiz))
            if not archivo.is_file() or EXCLUIR_BENIGNO.search(rel.lower()):
                continue
            t = tipo_archivo(archivo)
            if not t or t[1] != "codigo" or t[0] not in LENGUAJES:
                continue
            for u in segmentar(rel, leer(archivo), *t):
                if len(u.lineas) < 2 or DUDOSO.search(u.texto):
                    continue
                # en las muestras de NestJS cada ejemplo es un proyecto independiente
                grupo = "/".join(Path(rel).parts[:3]) if "nest-samples" in rel else proyecto.name
                candidatas.append((grupo, rel, u))
        if len(candidatas) > max_por_proyecto:
            idx = rng.choice(len(candidatas), max_por_proyecto, replace=False)
            candidatas = [candidatas[i] for i in sorted(idx)]
        for grupo, rel, u in candidatas:
            filas.append(registro("benigno", f"benigno:{grupo}", rel, u, 0, origen="código de producción de un proyecto open source"))
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
    """Partición por grupo de origen (proyecto / archivo de prueba / familia de casos).

    Todas las unidades de un mismo grupo quedan en la misma partición, evitando fugas entre
    entrenamiento, validación y prueba. La asignación se estratifica por la categoría principal.
    """
    from sklearn.model_selection import StratifiedGroupKFold

    estrato = df.apply(lambda r: (r["owasp2025"].split(";")[0] if r["vulnerable"] else "seguro") + "|" + r["subtipo"], axis=1)
    conteo = estrato.value_counts()
    estrato = estrato.where(estrato.map(conteo) >= 20, "otros")
    folds = np.zeros(len(df), dtype=int)
    sgkf = StratifiedGroupKFold(n_splits=20, shuffle=True, random_state=SEMILLA)
    for k, (_, idx) in enumerate(sgkf.split(df, estrato, groups=df["proyecto"])):
        folds[idx] = k
    n_test = round(20 * prop[2])
    n_val = round(20 * prop[1])
    particion = np.where(folds < n_test, "prueba", np.where(folds < n_test + n_val, "validacion", "entrenamiento"))
    return particion


def main():
    cargadores = [("semgrep", cargar_semgrep), ("codeql", cargar_codeql), ("benchmark", cargar_benchmark),
                  ("kics", cargar_kics), ("securityeval", cargar_securityeval), ("controlados", cargar_controlados),
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
